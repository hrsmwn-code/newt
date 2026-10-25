package fallback

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"time"
)

// Echo protocol used by auto mode to test whether UDP reaches the server.
// The fallback-relay replies to a request with the identical bytes. It is a
// separate port from Gerbil, so probing never touches WireGuard state.
var echoMagic = []byte("PANGOLIN_FALLBACK_ECHO1")

const (
	echoNonceLen   = 16
	echoRequestLen = 23 + echoNonceLen // len(echoMagic) + nonce
	echoAttempts   = 3
)

// IsEchoRequest reports whether b is a well-formed echo request.
func IsEchoRequest(b []byte) bool {
	return len(b) == echoRequestLen && bytes.HasPrefix(b, echoMagic)
}

func newEchoRequest() []byte {
	b := make([]byte, echoRequestLen)
	copy(b, echoMagic)
	_, _ = rand.Read(b[len(echoMagic):])
	return b
}

// probeEcho sends up to echoAttempts echo requests to every address over a
// fresh UDP socket, spread across timeout, and reports whether any matching
// reply arrived. It never uses the WireGuard socket.
func probeEcho(ctx context.Context, addrs []netip.Addr, port int, timeout time.Duration) bool {
	if len(addrs) == 0 || port <= 0 || port > 65535 {
		return false
	}
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return false
	}
	defer conn.Close()

	req := newEchoRequest()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)

	got := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], req) {
				close(got)
				return
			}
		}
	}()

	interval := timeout / echoAttempts
	if interval <= 0 {
		interval = timeout
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for i := 0; ; i++ {
		if i < echoAttempts {
			for _, a := range addrs {
				_, _ = conn.WriteToUDPAddrPort(req, netip.AddrPortFrom(a.Unmap(), uint16(port)))
			}
		}
		select {
		case <-got:
			return true
		case <-ctx.Done():
			return false
		case <-t.C:
			if !time.Now().Before(deadline) {
				return false
			}
		}
	}
}
