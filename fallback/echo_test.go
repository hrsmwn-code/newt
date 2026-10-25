package fallback

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// startEchoServer runs a UDP server that answers like the fallback-relay
// echo responder when respond is true, and stays silent otherwise.
func startEchoServer(t *testing.T, respond bool) (netip.Addr, int) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if respond && IsEchoRequest(buf[:n]) {
				_, _ = c.WriteToUDP(buf[:n], addr)
			}
		}
	}()
	return netip.MustParseAddr("127.0.0.1"), c.LocalAddr().(*net.UDPAddr).Port
}

func TestProbeEchoSuccess(t *testing.T) {
	ip, port := startEchoServer(t, true)
	if !probeEcho(context.Background(), []netip.Addr{ip}, port, time.Second) {
		t.Fatal("expected echo success")
	}
}

func TestProbeEchoSilentServer(t *testing.T) {
	ip, port := startEchoServer(t, false)
	start := time.Now()
	if probeEcho(context.Background(), []netip.Addr{ip}, port, 300*time.Millisecond) {
		t.Fatal("expected echo failure")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("probe must respect its timeout")
	}
}

func TestProbeEchoNoAddrs(t *testing.T) {
	if probeEcho(context.Background(), nil, 1, 100*time.Millisecond) {
		t.Fatal("no addresses -> failure")
	}
}

func TestProbeEchoIgnoresWrongReply(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			_, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP([]byte("not an echo"), addr)
		}
	}()
	port := c.LocalAddr().(*net.UDPAddr).Port
	if probeEcho(context.Background(), []netip.Addr{netip.MustParseAddr("127.0.0.1")}, port, 300*time.Millisecond) {
		t.Fatal("a reply that doesn't echo our nonce must not count")
	}
}

func TestIsEchoRequest(t *testing.T) {
	req := newEchoRequest()
	if !IsEchoRequest(req) {
		t.Fatal("newEchoRequest must be an echo request")
	}
	if IsEchoRequest([]byte("PANGOLIN_TEST_REQ12345678")) || IsEchoRequest(req[:len(req)-1]) {
		t.Fatal("wrong prefix/length must not match")
	}
}
