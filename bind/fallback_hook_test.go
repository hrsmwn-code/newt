//go:build !js

package bind

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/fosrl/newt/fallback"
	"github.com/gorilla/websocket"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// echoRelay answers every frame with the same payload, from port+1.
func echoRelay(t *testing.T) string {
	t.Helper()
	up := websocket.Upgrader{Subprotocols: []string{fallback.Subprotocol}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, msg, err := c.ReadMessage()
			if err != nil || len(msg) < 3 {
				return
			}
			port := uint16(msg[0])<<8 | uint16(msg[1])
			port++
			out := append([]byte{byte(port >> 8), byte(port)}, msg[2:]...)
			_ = c.WriteMessage(websocket.BinaryMessage, out)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func installTCPTransport(t *testing.T) netip.Addr {
	t.Helper()
	tr, err := fallback.New(fallback.Settings{Mode: fallback.ModeTCP}, echoRelay(t))
	if err != nil {
		t.Fatal(err)
	}
	tr.SetCredentials(fallback.Credentials{ClientType: "olm", ID: "o1", Token: "tok"})
	fallback.Install(tr)
	t.Cleanup(func() {
		fallback.Install(nil)
		tr.Close()
	})
	return netip.MustParseAddr("127.0.0.1") // relay host = server address
}

func udpListener(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

func expectNoUDP(t *testing.T, c *net.UDPConn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if n, _, err := c.ReadFromUDP(make([]byte, 256)); err == nil {
		t.Fatalf("tcp mode leaked %d bytes over UDP", n)
	}
}

type received struct {
	b  []byte
	ep wgConn.Endpoint
}

// startReceivers runs one goroutine per receive func, like wireguard-go.
func startReceivers(t *testing.T, fns []wgConn.ReceiveFunc) chan received {
	t.Helper()
	ch := make(chan received, 64)
	for _, fn := range fns {
		fn := fn
		go func() {
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			eps := []wgConn.Endpoint{nil}
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					ch <- received{append([]byte(nil), bufs[i][:sizes[i]]...), eps[i]}
				}
			}
		}()
	}
	return ch
}

func next(t *testing.T, ch chan received) ([]byte, wgConn.Endpoint) {
	t.Helper()
	select {
	case r := <-ch:
		return r.b, r.ep
	case <-time.After(3 * time.Second):
		t.Fatal("nothing received")
	}
	return nil, nil
}

func newBind(t *testing.T) *SharedBind {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestFallbackTCPHolePunchGoesOverRelay(t *testing.T) {
	server := installTCPTransport(t)
	gerbil, gport := udpListener(t)
	b := newBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	rx := startReceivers(t, fns)

	n, err := b.WriteToUDP([]byte("holepunch"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(server, gport)))
	if err != nil || n != len("holepunch") {
		t.Fatalf("WriteToUDP n=%d err=%v", n, err)
	}
	data, ep := next(t, rx)
	if string(data) != "holepunch" {
		t.Fatalf("got %q", data)
	}
	if ep.DstToString() != netip.AddrPortFrom(server, gport+1).String() {
		t.Fatalf("endpoint %s", ep.DstToString())
	}
	expectNoUDP(t, gerbil)
}

func TestFallbackTCPWireGuardSendGoesOverRelay(t *testing.T) {
	server := installTCPTransport(t)
	gerbil, gport := udpListener(t)
	b := newBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	rx := startReceivers(t, fns)
	ep := &wgConn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(server, gport)}
	if err := b.Send([][]byte{[]byte("wg1"), []byte("wg2")}, ep); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for len(got) < 2 {
		d, _ := next(t, rx)
		got[string(d)] = true
	}
	if !got["wg1"] || !got["wg2"] {
		t.Fatalf("got %v", got)
	}
	expectNoUDP(t, gerbil)

	// replies from the relay must not be treated as netstack endpoints:
	// sending back to them must go to the relay again, not netstack
	reply := &wgConn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(server, gport+1)}
	if err := b.Send([][]byte{[]byte("wg3")}, reply); err != nil {
		t.Fatal(err)
	}
	if d, _ := next(t, rx); string(d) != "wg3" {
		t.Fatalf("got %q", d)
	}
}

func TestFallbackTCPDropsPeerToPeerUDP(t *testing.T) {
	installTCPTransport(t)
	b := newBind(t)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skip("127.0.0.2 not available")
	}
	defer peer.Close()
	paddr := peer.LocalAddr().(*net.UDPAddr)
	if _, err := b.WriteToUDP([]byte("direct"), paddr); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{[]byte("direct")}, &wgConn.StdNetEndpoint{AddrPort: paddr.AddrPort()}); err != nil {
		t.Fatal(err)
	}
	expectNoUDP(t, peer)
}

func magicRequest() []byte {
	req := make([]byte, MagicTestRequestLen)
	copy(req, MagicTestRequest)
	copy(req[len(MagicTestRequest):], "12345678")
	return req
}

func TestFallbackTCPMagicRequestOverUDPGetsNoUDPReply(t *testing.T) {
	installTCPTransport(t)
	b := newBind(t)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	startReceivers(t, fns)

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skip("127.0.0.2 not available")
	}
	defer peer.Close()
	if _, err := peer.WriteToUDP(magicRequest(), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}); err != nil {
		t.Fatal(err)
	}
	expectNoUDP(t, peer)
}

func TestFallbackTCPMagicRequestViaRelayIsAnsweredViaRelay(t *testing.T) {
	server := installTCPTransport(t)
	gerbil, gport := udpListener(t)
	b := newBind(t)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	rx := startReceivers(t, fns)
	// prime the relay link so replies are attributed to the server
	if _, err := b.WriteToUDP([]byte("prime"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(server, gport))); err != nil {
		t.Fatal(err)
	}
	next(t, rx)

	// a magic request arriving over the relay is answered over the relay
	// (the echo relay then bounces the response back to us), never UDP
	b.injectFromRelay(magicRequest(), netip.AddrPortFrom(server, gport))
	expectNoUDP(t, gerbil)
}

func TestFallbackCloseRaceDoesNotLeakSocket(t *testing.T) {
	installTCPTransport(t)
	for i := 0; i < 200; i++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		b, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = b.WriteToUDP([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		}()
		_ = b.Close()
		<-done
		if b.fbSock.Load() != nil {
			t.Fatal("fallback socket created after/while closing")
		}
	}
}

func TestFallbackTCPClosedBindNeverSendsUDP(t *testing.T) {
	server := installTCPTransport(t)
	gerbil, gport := udpListener(t)
	ep := &wgConn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(server, gport)}

	b := newBind(t)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	// Simulate the window where closeFallback has run but the UDP socket
	// is still open (Send passed its closed check just before).
	b.closeFallback()
	if err := b.Send([][]byte{[]byte("late")}, ep); err != nil && err != net.ErrClosed {
		t.Fatalf("unexpected error %v", err)
	}
	if _, err := b.WriteToUDP([]byte("late"), net.UDPAddrFromAddrPort(ep.AddrPort)); err != nil && err != net.ErrClosed {
		t.Fatalf("unexpected error %v", err)
	}
	expectNoUDP(t, gerbil)
}

// Not run with -race: concurrent Send/Close also exercises upstream's
// unsynchronised `b.netstackEndpoints = sync.Map{}` in closeConnection,
// which is an upstream race outside this fork's hooks.
func TestFallbackTCPSendCloseRace(t *testing.T) {
	if raceEnabled {
		t.Skip("hits upstream SharedBind.closeConnection race on netstackEndpoints")
	}
	server := installTCPTransport(t)
	gerbil, gport := udpListener(t)
	ep := &wgConn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(server, gport)}
	for i := 0; i < 200; i++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			t.Fatal(err)
		}
		b, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = b.Send([][]byte{[]byte("x")}, ep)
		}()
		_ = b.Close()
		<-done
	}
	expectNoUDP(t, gerbil)
}

func TestFallbackNoTransportIsUpstreamBehaviour(t *testing.T) {
	fallback.Install(nil)
	gerbil, gport := udpListener(t)
	b := newBind(t)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.WriteToUDP([]byte("udp"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(gport)}); err != nil {
		t.Fatal(err)
	}
	_ = gerbil.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := gerbil.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "udp" {
		t.Fatalf("expected plain UDP, n=%d err=%v", n, err)
	}
}
