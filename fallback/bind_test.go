package fallback

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func TestWrapBindNilTransportReturnsInner(t *testing.T) {
	var tr *Transport
	inner := conn.NewStdNetBind()
	if tr.WrapBind(inner) != inner {
		t.Fatal("nil transport must return the inner bind unchanged")
	}
}

// receiveOne runs every receive func until one yields a packet.
func receiveOne(t *testing.T, fns []conn.ReceiveFunc) ([]byte, conn.Endpoint) {
	t.Helper()
	type res struct {
		b  []byte
		ep conn.Endpoint
	}
	ch := make(chan res, len(fns))
	for _, fn := range fns {
		fn := fn
		go func() {
			bufs := [][]byte{make([]byte, 2048)}
			sizes := []int{0}
			eps := []conn.Endpoint{nil}
			for {
				n, err := fn(bufs, sizes, eps)
				if err != nil {
					return
				}
				if n > 0 {
					ch <- res{append([]byte(nil), bufs[0][:sizes[0]]...), eps[0]}
					return
				}
			}
		}()
	}
	select {
	case r := <-ch:
		return r.b, r.ep
	case <-time.After(3 * time.Second):
		t.Fatal("no packet received")
	}
	return nil, nil
}

func TestWrapBindTCPModeUsesRelay(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)

	// a real UDP listener standing in for Gerbil: must receive nothing
	gerbil, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gerbil.Close()
	gport := uint16(gerbil.LocalAddr().(*net.UDPAddr).Port)

	b := tr.WrapBind(conn.NewStdNetBind())
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ep, err := b.ParseEndpoint(netip.AddrPortFrom(serverIP, gport).String())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{[]byte("wg-data")}, ep); err != nil {
		t.Fatal(err)
	}

	data, from := receiveOne(t, fns)
	if string(data) != "wg-data" {
		t.Fatalf("got %q", data)
	}
	if from.DstToString() != netip.AddrPortFrom(serverIP, gport+1).String() {
		t.Fatalf("relay reply endpoint %s", from.DstToString())
	}

	_ = gerbil.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := gerbil.ReadFromUDP(make([]byte, 64)); err == nil {
		t.Fatalf("tcp mode leaked %d bytes over UDP", n)
	}
}

func TestWrapBindUDPModeUsesUDP(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeUDP, fr, 1)

	gerbil, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer gerbil.Close()
	gport := uint16(gerbil.LocalAddr().(*net.UDPAddr).Port)

	b := tr.WrapBind(conn.NewStdNetBind())
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ep, _ := b.ParseEndpoint(netip.AddrPortFrom(serverIP, gport).String())
	if err := b.Send([][]byte{[]byte("over-udp")}, ep); err != nil {
		t.Fatal(err)
	}
	_ = gerbil.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := gerbil.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "over-udp" {
		t.Fatalf("udp mode must send over UDP: n=%d err=%v", n, err)
	}
}

func TestWrapBindCloseUnblocksRelayReceive(t *testing.T) {
	fr := newFakeRelay(t)
	tr := newTestTransport(t, ModeTCP, fr, 1)
	b := tr.WrapBind(conn.NewStdNetBind())
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, len(fns))
	for _, fn := range fns {
		fn := fn
		go func() {
			_, err := fn([][]byte{make([]byte, 2048)}, []int{0}, []conn.Endpoint{nil})
			done <- err
		}()
	}
	time.Sleep(50 * time.Millisecond)
	_ = b.Close()
	for range fns {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("receive after close must return an error")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("receive func not unblocked by Close")
		}
	}
	// reopen works (wireguard-go does Close/Open on BindUpdate)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	_ = b.Close()
}
