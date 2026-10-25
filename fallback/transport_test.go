package fallback

import (
	"bytes"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// toggleEcho is a UDP echo responder that can be switched on and off.
type toggleEcho struct {
	on   atomic.Bool
	port int
}

func newToggleEcho(t *testing.T, on bool) *toggleEcho {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	e := &toggleEcho{port: c.LocalAddr().(*net.UDPAddr).Port}
	e.on.Store(on)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if e.on.Load() && IsEchoRequest(buf[:n]) {
				_, _ = c.WriteToUDP(buf[:n], addr)
			}
		}
	}()
	return e
}

func fastTimings() timings {
	return timings{
		probeTimeout:     150 * time.Millisecond,
		probeMin:         200 * time.Millisecond,
		probeMax:         400 * time.Millisecond,
		handshakeTimeout: 300 * time.Millisecond,
	}
}

var serverIP = netip.MustParseAddr("127.0.0.1")

func newTestTransport(t *testing.T, mode Mode, fr *fakeRelay, echoPort int) *Transport {
	t.Helper()
	tr, err := New(Settings{Mode: mode, RelayPath: "/fallback-relay", EchoPort: echoPort}, fr.srv.URL,
		withTimings(fastTimings()), withTickInterval(20*time.Millisecond), withLinkBackoff(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.Close)
	tr.SetCredentials(Credentials{ClientType: "newt", ID: "n1", Token: "tok"})
	tr.AddServerAddr(serverIP)
	return tr
}

type delivery struct {
	data []byte
	from netip.AddrPort
}

func collector() (func([]byte, netip.AddrPort), chan delivery) {
	ch := make(chan delivery, 64)
	return func(b []byte, from netip.AddrPort) {
		ch <- delivery{append([]byte(nil), b...), from}
	}, ch
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNilTransportIsPassThrough(t *testing.T) {
	var tr *Transport
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, false)
	if s.Intercept([]byte{1}, netip.MustParseAddrPort("1.2.3.4:51820")) {
		t.Fatal("nil transport must never intercept")
	}
	if tr.ForceRelay() || tr.UsingRelay() {
		t.Fatal("nil transport reports no relay")
	}
	tr.SetCredentials(Credentials{})
	tr.AddServerAddr(serverIP)
	tr.NetworkChanged()
	tr.OnSwitch(func(bool) {})
	_ = s.Close()
}

func TestTCPModeSendsServerTrafficOverRelay(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	deliver, ch := collector()
	s := tr.NewSocket(deliver, false)
	defer s.Close()

	if !tr.ForceRelay() || !tr.UsingRelay() {
		t.Fatal("tcp mode must use the relay")
	}
	if !s.Intercept([]byte("hp"), netip.AddrPortFrom(serverIP, 21820)) {
		t.Fatal("tcp mode must intercept server traffic")
	}
	select {
	case d := <-ch:
		if !bytes.Equal(d.data, []byte("hp")) || d.from != netip.AddrPortFrom(serverIP, 21821) {
			t.Fatalf("got %+v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no reply through relay")
	}
}

func TestRelayRepliesComeFromTheAddressWeSentTo(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	other := netip.MustParseAddr("192.0.2.10")
	tr.AddServerAddr(other)
	deliver, ch := collector()
	s := tr.NewSocket(deliver, false)
	defer s.Close()

	for _, ip := range []netip.Addr{other, serverIP, other} {
		s.Intercept([]byte("x"), netip.AddrPortFrom(ip, 21820))
		select {
		case d := <-ch:
			if d.from.Addr() != ip {
				t.Fatalf("reply from %s, want %s", d.from.Addr(), ip)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no reply")
		}
	}
}

func TestTCPModeDropsNonServerUDP(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	deliver, ch := collector()
	s := tr.NewSocket(deliver, false)
	defer s.Close()
	waitFor(t, "relay connect", func() bool { return s.link.connected.Load() })
	if !s.Intercept([]byte("x"), netip.MustParseAddrPort("192.0.2.7:4000")) {
		t.Fatal("tcp mode must swallow (drop) non-server UDP")
	}
	select {
	case d := <-ch:
		t.Fatalf("non-server traffic must not go to the relay, got echo %+v", d)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUDPModeNeverIntercepts(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeUDP, fr, 1)
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, true)
	defer s.Close()
	for i := 0; i < 5; i++ {
		if s.Intercept(handshakeInit(), netip.AddrPortFrom(serverIP, 51820)) {
			t.Fatal("udp mode must never intercept")
		}
	}
	time.Sleep(500 * time.Millisecond)
	if tr.UsingRelay() || fr.requestCount() != 0 {
		t.Fatal("udp mode must never use the relay")
	}
}

func TestAutoStaysOnUDPWhenEchoWorks(t *testing.T) {
	fr := newFakeRelay(t)
	echo := newToggleEcho(t, true)
	tr := newTestTransport(t, ModeAuto, fr, echo.port)
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, false)
	defer s.Close()

	waitFor(t, "decision", func() bool { return tr.State() == "udp" })
	if s.Intercept([]byte("x"), netip.AddrPortFrom(serverIP, 21820)) {
		t.Fatal("auto on UDP must not intercept")
	}
	if fr.requestCount() != 0 {
		t.Fatal("relay must not be used when UDP works")
	}
}

func TestAutoFallsBackAndReturns(t *testing.T) {
	fr := newFakeRelay(t)
	echo := newToggleEcho(t, false)
	tr := newTestTransport(t, ModeAuto, fr, echo.port)

	var mu sync.Mutex
	var switches []bool
	tr.OnSwitch(func(relay bool) {
		mu.Lock()
		switches = append(switches, relay)
		mu.Unlock()
	})
	deliver, ch := collector()
	s := tr.NewSocket(deliver, false)
	defer s.Close()

	waitFor(t, "fallback", func() bool { return tr.UsingRelay() })
	if !s.Intercept([]byte("a"), netip.AddrPortFrom(serverIP, 21820)) {
		t.Fatal("auto on relay must intercept server traffic")
	}
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("no reply through relay")
	}

	echo.on.Store(true)
	waitFor(t, "switch back to UDP", func() bool { return tr.State() == "udp" })
	if s.Intercept([]byte("b"), netip.AddrPortFrom(serverIP, 21820)) {
		t.Fatal("back on UDP must not intercept")
	}
	waitFor(t, "relay connection closed", func() bool {
		fr.mu.Lock()
		defer fr.mu.Unlock()
		return s.link.connected.Load() == false
	})
	mu.Lock()
	defer mu.Unlock()
	if len(switches) < 2 || !switches[0] || switches[len(switches)-1] {
		t.Fatalf("switch callbacks %v", switches)
	}
}

func handshakeInit() []byte {
	b := make([]byte, 148)
	b[0] = 1
	return b
}

func TestVerifyingSocketFallsBackOnHandshakeTimeout(t *testing.T) {
	fr := newFakeRelay(t)
	echo := newToggleEcho(t, true)
	tr := newTestTransport(t, ModeAuto, fr, echo.port)
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, true)
	defer s.Close()

	waitFor(t, "udp", func() bool { return tr.State() == "udp" })
	if s.Intercept(handshakeInit(), netip.AddrPortFrom(serverIP, 51820)) {
		t.Fatal("handshake on UDP must go over UDP")
	}
	waitFor(t, "fallback after handshake timeout", func() bool { return tr.UsingRelay() })
}

func TestVerifyingSocketHandshakeResponseKeepsUDP(t *testing.T) {
	fr := newFakeRelay(t)
	echo := newToggleEcho(t, true)
	tr := newTestTransport(t, ModeAuto, fr, echo.port)
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, true)
	defer s.Close()

	waitFor(t, "udp", func() bool { return tr.State() == "udp" })
	s.Intercept(handshakeInit(), netip.AddrPortFrom(serverIP, 51820))
	resp := make([]byte, 92)
	resp[0] = 2
	s.ObserveUDP(resp, netip.AddrPortFrom(serverIP, 51820))
	time.Sleep(600 * time.Millisecond)
	if tr.State() != "udp" {
		t.Fatal("handshake response must keep UDP")
	}
}

func TestSocketCloseClosesLink(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	s := tr.NewSocket(func([]byte, netip.AddrPort) {}, false)
	s.Intercept([]byte("x"), netip.AddrPortFrom(serverIP, 21820))
	waitFor(t, "connect", func() bool { return s.link.connected.Load() })
	_ = s.Close()
	if s.Intercept([]byte("x"), netip.AddrPortFrom(serverIP, 21820)) != true {
		t.Fatal("closed socket in tcp mode still swallows (drops) server traffic")
	}
	waitFor(t, "link closed", func() bool { return !s.link.connected.Load() })
}

func TestDefaultTransport(t *testing.T) {
	if Default() != nil {
		t.Fatal("no default transport before Install")
	}
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	Install(tr)
	defer Install(nil)
	if Default() != tr {
		t.Fatal("Install must set the default transport")
	}
}
