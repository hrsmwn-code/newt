package fallback

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeRelay is a minimal in-process relay: it records the handshake request
// and echoes every frame back with port+1.
type fakeRelay struct {
	srv *httptest.Server

	mu       sync.Mutex
	requests []*http.Request
	conns    []*websocket.Conn
	reject   bool
}

func newFakeRelay(t *testing.T) *fakeRelay {
	t.Helper()
	fr := &fakeRelay{}
	up := websocket.Upgrader{Subprotocols: []string{Subprotocol}}
	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.requests = append(fr.requests, r)
		reject := fr.reject
		fr.mu.Unlock()
		if reject {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		fr.mu.Lock()
		fr.conns = append(fr.conns, c)
		fr.mu.Unlock()
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			port, payload, err := parseFrame(msg)
			if err != nil {
				continue
			}
			_ = c.WriteMessage(websocket.BinaryMessage, appendFrame(nil, port+1, payload))
		}
	}))
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRelay) dropAll() {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	for _, c := range fr.conns {
		c.Close()
	}
	fr.conns = nil
}

func (fr *fakeRelay) requestCount() int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return len(fr.requests)
}

type recvd struct {
	port    uint16
	payload []byte
}

func newTestLink(t *testing.T, fr *fakeRelay, creds Credentials) (*link, chan recvd) {
	t.Helper()
	ch := make(chan recvd, 16)
	u, err := RelayURL(fr.srv.URL, "/fallback-relay")
	if err != nil {
		t.Fatal(err)
	}
	l := newLink(linkConfig{
		relayURL:    u,
		credentials: func() Credentials { return creds },
		onRecv: func(port uint16, payload []byte) {
			ch <- recvd{port, append([]byte(nil), payload...)}
		},
		backoffMin: 10 * time.Millisecond,
		backoffMax: 50 * time.Millisecond,
	})
	t.Cleanup(l.close)
	return l, ch
}

func waitRecv(t *testing.T, ch chan recvd) recvd {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for datagram from relay")
	}
	return recvd{}
}

func TestLinkSendsCredentialsAndRoundTrips(t *testing.T) {
	fr := newFakeRelay(t)
	l, ch := newTestLink(t, fr, Credentials{ClientType: "newt", ID: "abc", Token: "tok"})

	l.send(51820, []byte("ping"))
	r := waitRecv(t, ch)
	if r.port != 51821 || !bytes.Equal(r.payload, []byte("ping")) {
		t.Fatalf("got %+v", r)
	}

	fr.mu.Lock()
	req := fr.requests[0]
	fr.mu.Unlock()
	if req.URL.Path != "/fallback-relay" {
		t.Fatalf("path %q", req.URL.Path)
	}
	if req.Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("auth header %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get(HeaderClientType) != "newt" || req.Header.Get(HeaderClientID) != "abc" {
		t.Fatalf("headers %v", req.Header)
	}
	if strings.Contains(req.URL.RawQuery, "tok") {
		t.Fatal("token must not be sent in the URL")
	}
}

func TestLinkDoesNotDialWithoutCredentials(t *testing.T) {
	fr := newFakeRelay(t)
	l, _ := newTestLink(t, fr, Credentials{})
	l.send(51820, []byte("x"))
	time.Sleep(100 * time.Millisecond)
	if fr.requestCount() != 0 {
		t.Fatal("must not dial without a token")
	}
}

func TestLinkReconnects(t *testing.T) {
	fr := newFakeRelay(t)
	l, ch := newTestLink(t, fr, Credentials{ClientType: "olm", ID: "o", Token: "t"})

	l.send(21820, []byte("a"))
	waitRecv(t, ch)
	fr.dropAll()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l.send(21820, []byte("b"))
		select {
		case r := <-ch:
			if string(r.payload) == "b" {
				if fr.requestCount() < 2 {
					t.Fatal("expected a second dial")
				}
				return
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	t.Fatal("link did not reconnect")
}

func TestLinkSendDropsWhenNotConnected(t *testing.T) {
	fr := newFakeRelay(t)
	fr.reject = true
	l, _ := newTestLink(t, fr, Credentials{ClientType: "newt", ID: "a", Token: "t"})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			l.send(51820, []byte("x"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("send must never block")
	}
}

func TestLinkCloseStopsDialing(t *testing.T) {
	fr := newFakeRelay(t)
	fr.reject = true
	l, _ := newTestLink(t, fr, Credentials{ClientType: "newt", ID: "a", Token: "t"})
	l.send(51820, []byte("x"))
	time.Sleep(100 * time.Millisecond)
	l.close()
	n := fr.requestCount()
	time.Sleep(200 * time.Millisecond)
	if fr.requestCount() != n {
		t.Fatal("dialing continued after close")
	}
}

func TestRelayURL(t *testing.T) {
	cases := []struct{ endpoint, path, want string }{
		{"https://pangolin.example.com", "/fallback-relay", "wss://pangolin.example.com/fallback-relay"},
		{"https://pangolin.example.com/", "/x", "wss://pangolin.example.com/x"},
		{"http://10.0.0.1:3000", "/fallback-relay", "ws://10.0.0.1:3000/fallback-relay"},
		{"pangolin.example.com", "/fallback-relay", "wss://pangolin.example.com/fallback-relay"},
	}
	for _, c := range cases {
		got, err := RelayURL(c.endpoint, c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("RelayURL(%q,%q) = %q, want %q", c.endpoint, c.path, got, c.want)
		}
	}
}
