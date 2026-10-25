package fallback

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// WrapBind wraps a wireguard-go Bind (the Newt main tunnel) so datagrams to
// the server follow the transport decision. A nil Transport returns inner.
func (t *Transport) WrapBind(inner conn.Bind) conn.Bind {
	if t == nil {
		return inner
	}
	return &wrappedBind{t: t, inner: inner}
}

type relayPacket struct {
	data []byte
	from netip.AddrPort
}

type wrappedBind struct {
	t     *Transport
	inner conn.Bind

	mu     sync.Mutex
	sock   *Socket
	in     chan relayPacket
	closed chan struct{}
}

func (b *wrappedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}

	in := make(chan relayPacket, 1024)
	closed := make(chan struct{})
	sock := b.t.NewSocket(func(data []byte, from netip.AddrPort) {
		select {
		case in <- relayPacket{append([]byte(nil), data...), from}:
		case <-closed:
		default: // full: drop
		}
	}, true)

	b.mu.Lock()
	b.sock, b.in, b.closed = sock, in, closed
	b.mu.Unlock()

	wrapped := make([]conn.ReceiveFunc, 0, len(fns)+1)
	for _, fn := range fns {
		wrapped = append(wrapped, b.observe(fn, sock))
	}
	wrapped = append(wrapped, b.receiveRelay(in, closed))
	return wrapped, actual, nil
}

// observe passes UDP receives through, letting the socket watch for
// WireGuard handshake responses from the server.
func (b *wrappedBind) observe(fn conn.ReceiveFunc, sock *Socket) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(bufs, sizes, eps)
		for i := 0; i < n; i++ {
			if eps[i] == nil {
				continue
			}
			if ap, perr := netip.ParseAddrPort(eps[i].DstToString()); perr == nil {
				sock.ObserveUDP(bufs[i][:sizes[i]], ap)
			}
		}
		return n, err
	}
}

func (b *wrappedBind) receiveRelay(in chan relayPacket, closed chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case p := <-in:
			if len(p.data) > len(bufs[0]) {
				return 0, nil
			}
			ep, err := b.inner.ParseEndpoint(p.from.String())
			if err != nil {
				return 0, nil
			}
			sizes[0] = copy(bufs[0], p.data)
			eps[0] = ep
			return 1, nil
		}
	}
}

func (b *wrappedBind) Close() error {
	b.mu.Lock()
	sock, closed := b.sock, b.closed
	b.sock, b.closed = nil, nil
	b.mu.Unlock()
	if closed != nil {
		close(closed)
	}
	if sock != nil {
		_ = sock.Close()
	}
	return b.inner.Close()
}

func (b *wrappedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	sock := b.sock
	b.mu.Unlock()
	if sock != nil {
		dst, err := netip.ParseAddrPort(ep.DstToString())
		if err == nil {
			// Intercept per buffer; keep the UDP batch for the rest.
			pass := bufs[:0:0]
			for _, buf := range bufs {
				if !sock.Intercept(buf, dst) {
					pass = append(pass, buf)
				}
			}
			if len(pass) == 0 {
				return nil
			}
			bufs = pass
		}
	}
	return b.inner.Send(bufs, ep)
}

func (b *wrappedBind) SetMark(mark uint32) error { return b.inner.SetMark(mark) }

func (b *wrappedBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.inner.ParseEndpoint(s)
}

func (b *wrappedBind) BatchSize() int { return b.inner.BatchSize() }
