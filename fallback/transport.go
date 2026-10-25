package fallback

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/util"
)

// Transport is the process-wide fallback decision. Every UDP socket that
// talks to the Pangolin server registers a Socket with it; all sockets
// follow the same UDP/relay decision, but each gets its own relay
// connection so Gerbil keeps seeing them as distinct senders.
//
// A nil *Transport is valid and behaves as a pass-through (upstream
// behaviour), so hooks in upstream code don't need nil checks.
type Transport struct {
	settings Settings
	relayURL string
	tm       timings
	tick     time.Duration
	linkMin  time.Duration
	tls      *tls.Config

	mu       sync.Mutex
	ctrl     *controller
	creds    Credentials
	sockets  map[*Socket]struct{}
	onSwitch []func(relay bool)

	servers sync.Map // netip.Addr -> struct{}
	state   atomic.Int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Option configures a Transport.
type Option func(*Transport)

// WithTLSConfig sets the TLS configuration for relay connections.
func WithTLSConfig(c *tls.Config) Option { return func(t *Transport) { t.tls = c } }

func withTimings(tm timings) Option           { return func(t *Transport) { t.tm = tm } }
func withTickInterval(d time.Duration) Option { return func(t *Transport) { t.tick = d } }
func withLinkBackoff(d time.Duration) Option  { return func(t *Transport) { t.linkMin = d } }

// New creates a Transport for the Pangolin server at endpoint
// (e.g. "https://pangolin.example.com").
func New(s Settings, endpoint string, opts ...Option) (*Transport, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	relayURL, err := RelayURL(endpoint, s.RelayPath)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		settings: s,
		relayURL: relayURL,
		tm:       defaultTimings(),
		tick:     time.Second,
		linkMin:  time.Second,
		sockets:  make(map[*Socket]struct{}),
	}
	for _, o := range opts {
		o(t)
	}
	if t.tls == nil && os.Getenv("SKIP_TLS_VERIFY") == "true" {
		t.tls = &tls.Config{InsecureSkipVerify: true}
	}
	t.ctrl = newController(s.Mode, t.tm)
	t.state.Store(int32(t.ctrl.state))
	t.ctx, t.cancel = context.WithCancel(context.Background())

	if u, err := url.Parse(relayURL); err == nil {
		t.AddServerHost(u.Hostname())
	}

	if s.Mode != ModeUDP {
		logger.Info("fallback: transport mode %q, relay %s", s.Mode, relayURL)
	}
	if s.Mode == ModeAuto {
		t.wg.Add(1)
		go t.loop()
	}
	return t, nil
}

var defaultTransport atomic.Pointer[Transport]

// Install makes t the process default used by hooks in upstream code.
func Install(t *Transport) { defaultTransport.Store(t) }

// Default returns the installed Transport, or nil (pass-through).
func Default() *Transport { return defaultTransport.Load() }

// Close stops probing and closes every relay connection.
func (t *Transport) Close() {
	if t == nil {
		return
	}
	t.cancel()
	t.wg.Wait()
	t.mu.Lock()
	socks := make([]*Socket, 0, len(t.sockets))
	for s := range t.sockets {
		socks = append(socks, s)
	}
	t.mu.Unlock()
	for _, s := range socks {
		_ = s.Close()
	}
}

// Mode returns the configured mode (ModeUDP for a nil Transport).
func (t *Transport) Mode() Mode {
	if t == nil {
		return ModeUDP
	}
	return t.settings.Mode
}

// ForceRelay reports whether the transport is in tcp mode.
func (t *Transport) ForceRelay() bool { return t != nil && t.settings.Mode == ModeTCP }

// UsingRelay reports whether server traffic currently goes over the relay.
func (t *Transport) UsingRelay() bool {
	return t != nil && pathState(t.state.Load()) == stateWS
}

// State returns "udp", "tcp" or "undecided".
func (t *Transport) State() string {
	if t == nil {
		return stateUDP.String()
	}
	return pathState(t.state.Load()).String()
}

// SetCredentials sets the session token used to authenticate relay links.
func (t *Transport) SetCredentials(c Credentials) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.creds = c
	t.mu.Unlock()
}

func (t *Transport) credentials() Credentials {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.creds
}

// AddServerAddr marks ip as a Pangolin server (Gerbil) address.
func (t *Transport) AddServerAddr(ip netip.Addr) {
	if t == nil || !ip.IsValid() {
		return
	}
	t.servers.Store(ip.Unmap(), struct{}{})
}

// AddServerHost resolves host (a hostname or IP, optionally host:port) and
// marks all its addresses as server addresses. Resolution failures are
// logged and ignored.
func (t *Transport) AddServerHost(host string) {
	if t == nil || host == "" {
		return
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip, err := netip.ParseAddr(host); err == nil {
		t.AddServerAddr(ip)
		return
	}
	ips, err := util.ResolveDomainAll(host)
	if err != nil {
		logger.Warn("fallback: cannot resolve server host %s: %v", host, err)
		return
	}
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil {
			t.AddServerAddr(ip)
		}
	}
}

func (t *Transport) isServer(ip netip.Addr) bool {
	_, ok := t.servers.Load(ip.Unmap())
	return ok
}

func (t *Transport) serverAddrs() []netip.Addr {
	var out []netip.Addr
	t.servers.Range(func(k, _ any) bool {
		out = append(out, k.(netip.Addr))
		return true
	})
	return out
}

// OnSwitch registers a callback invoked (outside locks) whenever the
// transport switches to the relay (true) or back to UDP (false).
func (t *Transport) OnSwitch(fn func(relay bool)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.onSwitch = append(t.onSwitch, fn)
	t.mu.Unlock()
}

// NetworkChanged should be called when the local network changes (e.g. a
// socket rebind on macOS). In auto mode it triggers an immediate re-probe.
func (t *Transport) NetworkChanged() {
	if t == nil {
		return
	}
	t.withCtrl(func(c *controller) { c.networkChanged(time.Now()) })
}

// withCtrl runs fn on the controller and applies any resulting state change.
func (t *Transport) withCtrl(fn func(c *controller)) {
	t.mu.Lock()
	before := t.ctrl.state
	fn(t.ctrl)
	after := t.ctrl.state
	reason := t.ctrl.lastReason
	var cbs []func(bool)
	var socks []*Socket
	if before != after {
		t.state.Store(int32(after))
		cbs = append(cbs, t.onSwitch...)
		for s := range t.sockets {
			socks = append(socks, s)
		}
	}
	t.mu.Unlock()

	if before == after {
		return
	}
	relay := after == stateWS
	if relay {
		logger.Info("fallback: switching to TCP 443 relay: %s", reason)
	} else {
		logger.Info("fallback: switching to UDP: %s", reason)
	}
	for _, s := range socks {
		s.link.setActive(relay)
	}
	if before == stateUndecided && !relay {
		return // initial decision for UDP is not a switch
	}
	for _, cb := range cbs {
		cb(relay)
	}
}

func (t *Transport) loop() {
	defer t.wg.Done()
	tk := time.NewTicker(t.tick)
	defer tk.Stop()
	for {
		var probe bool
		t.withCtrl(func(c *controller) { probe = c.tick(time.Now()) })
		if probe {
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				ok := probeEcho(t.ctx, t.serverAddrs(), t.settings.EchoPort, t.tm.probeTimeout)
				if t.ctx.Err() != nil {
					return
				}
				logger.Debug("fallback: UDP echo probe result: %v", ok)
				t.withCtrl(func(c *controller) { c.onProbeResult(ok, time.Now()) })
			}()
		}
		select {
		case <-t.ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// Socket is the per-UDP-socket view of the Transport.
type Socket struct {
	t         *Transport
	link      *link
	deliver   func(data []byte, from netip.AddrPort)
	verifying bool
	closeOnce sync.Once

	// lastDst is the server IP this socket last sent to over the relay;
	// relay replies are attributed to it so they match the WireGuard peer
	// endpoint / hole-punch target the client actually used.
	lastDst atomic.Pointer[netip.Addr]
}

// NewSocket registers a UDP socket. deliver is called with every datagram
// received from the server over the relay; it must inject the datagram into
// the socket's receive path as if it came from `from`. verifying marks the
// socket whose WireGuard peer is the server itself (the Newt main tunnel):
// its handshakes are used to detect UDP that passes the echo but not
// WireGuard.
func (t *Transport) NewSocket(deliver func(data []byte, from netip.AddrPort), verifying bool) *Socket {
	s := &Socket{t: t, deliver: deliver, verifying: verifying}
	if t == nil {
		return s
	}
	s.link = newLink(linkConfig{
		relayURL:    t.relayURL,
		credentials: t.credentials,
		tlsConfig:   t.tls,
		backoffMin:  t.linkMin,
		onRecv:      s.recvFromRelay,
	})
	t.mu.Lock()
	t.sockets[s] = struct{}{}
	relay := t.ctrl.state == stateWS
	t.mu.Unlock()
	if relay {
		s.link.setActive(true)
	}
	return s
}

// Close unregisters the socket and closes its relay connection.
func (s *Socket) Close() error {
	if s == nil || s.t == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.t.mu.Lock()
		delete(s.t.sockets, s)
		s.t.mu.Unlock()
		s.link.close()
	})
	return nil
}

func (s *Socket) recvFromRelay(port uint16, payload []byte) {
	if s.deliver == nil {
		return
	}
	p := s.lastDst.Load()
	if p == nil {
		return
	}
	s.deliver(payload, netip.AddrPortFrom(*p, port))
}

// Intercept must be called before sending data to dst over UDP. It returns
// true when the datagram was handled (sent over the relay, or dropped in tcp
// mode) and must NOT be sent over UDP.
func (s *Socket) Intercept(data []byte, dst netip.AddrPort) bool {
	if s == nil || s.t == nil {
		return false
	}
	t := s.t
	if !t.isServer(dst.Addr()) {
		// direct peer-to-peer traffic: UDP as upstream, except tcp mode,
		// which must never send UDP at all
		return t.settings.Mode == ModeTCP
	}
	if pathState(t.state.Load()) == stateWS {
		ip := dst.Addr().Unmap()
		if p := s.lastDst.Load(); p == nil || *p != ip {
			s.lastDst.Store(&ip)
		}
		s.link.send(dst.Port(), data)
		return true
	}
	if s.verifying && isHandshakeInitiation(data) {
		t.withCtrl(func(c *controller) { c.onHandshakeSent(time.Now()) })
	}
	return false
}

// ObserveUDP must be called for every datagram received over UDP.
func (s *Socket) ObserveUDP(data []byte, from netip.AddrPort) {
	if s == nil || s.t == nil || !s.verifying || !isHandshakeResponse(data) {
		return
	}
	if s.t.isServer(from.Addr()) {
		s.t.withCtrl(func(c *controller) { c.onServerRecv(true, time.Now()) })
	}
}

// WireGuard message types (first byte; the next 3 bytes are reserved zero).
func isHandshakeInitiation(b []byte) bool {
	return len(b) == 148 && b[0] == 1 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

func isHandshakeResponse(b []byte) bool {
	return len(b) == 92 && b[0] == 2 && b[1] == 0 && b[2] == 0 && b[3] == 0
}
