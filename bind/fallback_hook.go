//go:build !js

package bind

// Fork-only: TCP 443 fallback hooks for SharedBind. Upstream shared_bind.go
// only calls the helpers below, so rebases stay small.

import (
	"net"
	"net/netip"

	"github.com/fosrl/newt/fallback"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// fallbackSocket returns this bind's fallback socket, creating it on first
// use when a fallback transport is installed. Returns nil otherwise.
func (b *SharedBind) fallbackSocket() *fallback.Socket {
	if s := b.fbSock.Load(); s != nil {
		return s
	}
	t := fallback.Default()
	if t == nil {
		return nil
	}
	b.fbMu.Lock()
	defer b.fbMu.Unlock()
	if b.fbClosed.Load() || b.closed.Load() {
		return nil
	}
	if s := b.fbSock.Load(); s != nil {
		return s
	}
	s := t.NewSocket(b.injectFromRelay, false)
	b.fbSock.Store(s)
	return s
}

// injectFromRelay queues a datagram received over the relay into the
// netstack/injected receive path, without marking its source as a netstack
// endpoint (replies must go back through the relay, not netstack).
func (b *SharedBind) injectFromRelay(data []byte, from netip.AddrPort) {
	if b.closed.Load() {
		return
	}
	if b.handleMagicPacket(data, net.UDPAddrFromAddrPort(from)) {
		return
	}
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	select {
	case b.netstackPackets <- injectedPacket{data: dataCopy, endpoint: &wgConn.StdNetEndpoint{AddrPort: from}}:
	case <-b.closeChan:
	default:
	}
}

// fallbackIntercept reports whether data to dst was handled by the fallback
// (sent over the relay or dropped in tcp mode) and must not go over UDP.
func (b *SharedBind) fallbackIntercept(data []byte, dst netip.AddrPort) bool {
	s := b.fallbackSocket()
	if s == nil {
		// closed in tcp mode: still never fall through to UDP
		return (b.fbClosed.Load() || b.closed.Load()) && fallback.Default().ForceRelay()
	}
	if dst.Addr().Is4In6() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}
	return s.Intercept(data, dst)
}

// fallbackFilter returns the buffers that must still be sent over UDP to
// dst; the others were handled by the fallback.
func (b *SharedBind) fallbackFilter(bufs [][]byte, dst netip.AddrPort) [][]byte {
	if b.fallbackSocket() == nil {
		if (b.fbClosed.Load() || b.closed.Load()) && fallback.Default().ForceRelay() {
			return nil // closing in tcp mode: never fall through to UDP
		}
		return bufs
	}
	pass := bufs[:0:0]
	for _, buf := range bufs {
		if !b.fallbackIntercept(buf, dst) {
			pass = append(pass, buf)
		}
	}
	return pass
}

// closeFallback closes the fallback socket (and its relay connection).
func (b *SharedBind) closeFallback() {
	b.fbMu.Lock()
	b.fbClosed.Store(true)
	s := b.fbSock.Swap(nil)
	b.fbMu.Unlock()
	if s != nil {
		_ = s.Close()
	}
}
