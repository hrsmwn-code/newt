package fallback

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"
)

const (
	// HeaderClientType / HeaderClientID identify the caller to the relay; the
	// session token goes in "Authorization: Bearer <token>".
	HeaderClientType = "X-Fallback-Client-Type"
	HeaderClientID   = "X-Fallback-Client-Id"

	outQueueLen    = 1024
	pingInterval   = 20 * time.Second
	readTimeout    = 60 * time.Second
	writeTimeout   = 10 * time.Second
	dialTimeout    = 15 * time.Second
	maxMessageSize = 65535 + frameHeaderLen
)

// Credentials authenticate a link with the relay. They are the same session
// token / id the client already uses for Pangolin's control WebSocket.
type Credentials struct {
	ClientType string // "newt" or "olm"
	ID         string
	Token      string
}

// RelayURL builds the relay WebSocket URL from the Pangolin endpoint
// (e.g. https://pangolin.example.com) and the relay path.
func RelayURL(endpoint, path string) (string, error) {
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("fallback: invalid endpoint %q: %w", endpoint, err)
	}
	scheme := "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}
	if u.Host == "" {
		return "", fmt.Errorf("fallback: endpoint %q has no host", endpoint)
	}
	return scheme + "://" + u.Host + path, nil
}

type linkConfig struct {
	relayURL    string
	credentials func() Credentials
	onRecv      func(port uint16, payload []byte)
	onState     func(connected bool)

	tlsConfig *tls.Config
	netDial   func(ctx context.Context, network, addr string) (net.Conn, error)

	backoffMin time.Duration
	backoffMax time.Duration
}

// link is one WebSocket connection to the relay. It dials lazily (on the
// first send or activate), reconnects with backoff while active, and never
// blocks the caller: frames are dropped when the queue is full, which is
// fine for UDP semantics.
type link struct {
	cfg linkConfig
	out chan []byte

	mu     sync.Mutex
	active bool
	conn   *websocket.Conn

	wake      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	connected atomic.Bool
	wg        sync.WaitGroup
}

func newLink(cfg linkConfig) *link {
	if cfg.backoffMin <= 0 {
		cfg.backoffMin = time.Second
	}
	if cfg.backoffMax <= 0 {
		cfg.backoffMax = 30 * time.Second
	}
	l := &link{
		cfg:    cfg,
		out:    make(chan []byte, outQueueLen),
		wake:   make(chan struct{}, 1),
		closed: make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l
}

// setActive starts (true) or stops (false) maintaining the connection.
// Deactivating closes the current connection.
func (l *link) setActive(active bool) {
	l.mu.Lock()
	changed := l.active != active
	l.active = active
	conn := l.conn
	l.mu.Unlock()
	if !changed {
		return
	}
	if active {
		l.poke()
		return
	}
	if conn != nil {
		conn.Close()
	}
	l.drain()
}

func (l *link) isActive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}

func (l *link) poke() {
	select {
	case l.wake <- struct{}{}:
	default:
	}
}

func (l *link) drain() {
	for {
		select {
		case <-l.out:
		default:
			return
		}
	}
}

// send queues one datagram for the server port. It activates the link.
func (l *link) send(port uint16, payload []byte) {
	select {
	case <-l.closed:
		return
	default:
	}
	l.setActive(true)
	select {
	case l.out <- appendFrame(make([]byte, 0, frameHeaderLen+len(payload)), port, payload):
	default:
		// queue full: drop (UDP semantics)
	}
}

func (l *link) close() {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.mu.Lock()
		conn := l.conn
		l.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
	})
	l.wg.Wait()
}

// sleep waits for d, returning false if the link was closed.
func (l *link) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-l.closed:
		return false
	}
}

func (l *link) run() {
	defer l.wg.Done()
	backoff := l.cfg.backoffMin
	for {
		// wait until active
		for !l.isActive() {
			select {
			case <-l.closed:
				return
			case <-l.wake:
			}
		}

		creds := l.cfg.credentials()
		if creds.Token == "" {
			if !l.sleep(backoff) {
				return
			}
			continue
		}

		conn, err := l.dial(creds)
		if err != nil {
			logger.Warn("fallback: cannot connect to relay %s: %v (retrying in %v)", l.cfg.relayURL, err, backoff)
			if !l.sleep(backoff) {
				return
			}
			backoff *= 2
			if backoff > l.cfg.backoffMax {
				backoff = l.cfg.backoffMax
			}
			continue
		}
		backoff = l.cfg.backoffMin

		l.mu.Lock()
		stillActive := l.active
		if stillActive {
			l.conn = conn
		}
		l.mu.Unlock()
		select {
		case <-l.closed:
			conn.Close()
			return
		default:
		}
		if !stillActive {
			conn.Close()
			continue
		}

		logger.Info("fallback: connected to relay %s", l.cfg.relayURL)
		l.connected.Store(true)
		if l.cfg.onState != nil {
			l.cfg.onState(true)
		}
		l.serve(conn)
		l.connected.Store(false)
		if l.cfg.onState != nil {
			l.cfg.onState(false)
		}

		l.mu.Lock()
		if l.conn == conn {
			l.conn = nil
		}
		l.mu.Unlock()
		conn.Close()
		if l.isActive() {
			logger.Info("fallback: relay connection lost, reconnecting")
		}
	}
}

func (l *link) dial(creds Credentials) (*websocket.Conn, error) {
	d := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: dialTimeout,
		Subprotocols:     []string{Subprotocol},
		TLSClientConfig:  l.cfg.tlsConfig,
		NetDialContext:   l.cfg.netDial,
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+creds.Token)
	h.Set(HeaderClientType, creds.ClientType)
	h.Set(HeaderClientID, creds.ID)

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	conn, resp, err := d.DialContext(ctx, l.cfg.relayURL, h)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("%w (HTTP %d)", err, resp.StatusCode)
		}
		return nil, err
	}
	conn.SetReadLimit(maxMessageSize)
	return conn, nil
}

func (l *link) serve(conn *websocket.Conn) {
	readDone := make(chan struct{})
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	go func() {
		defer close(readDone)
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
			if mt != websocket.BinaryMessage {
				continue
			}
			port, payload, err := parseFrame(msg)
			if err != nil {
				continue
			}
			l.cfg.onRecv(port, payload)
		}
	}()

	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-l.closed:
			conn.Close()
			<-readDone
			return
		case <-readDone:
			return
		case frame := <-l.out:
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				conn.Close()
				<-readDone
				return
			}
		case <-ping.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				conn.Close()
				<-readDone
				return
			}
		}
	}
}
