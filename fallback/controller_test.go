package fallback

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestController(mode Mode) *controller {
	return newController(mode, defaultTimings())
}

func TestControllerFixedModes(t *testing.T) {
	c := newTestController(ModeTCP)
	if c.state != stateWS {
		t.Fatalf("tcp mode must start on WS, got %v", c.state)
	}
	if c.tick(t0.Add(time.Hour)) {
		t.Fatal("tcp mode must never ask for a UDP probe")
	}
	c.networkChanged(t0)
	if c.tick(t0) {
		t.Fatal("tcp mode must not probe after a network change")
	}

	u := newTestController(ModeUDP)
	if u.state != stateUDP {
		t.Fatalf("udp mode must start on UDP, got %v", u.state)
	}
	u.onHandshakeSent(t0)
	u.tick(t0.Add(time.Hour))
	if u.state != stateUDP {
		t.Fatal("udp mode must never fall back")
	}
}

func TestControllerAutoInitialProbe(t *testing.T) {
	c := newTestController(ModeAuto)
	if c.state != stateUndecided {
		t.Fatalf("auto starts undecided, got %v", c.state)
	}
	if !c.tick(t0) {
		t.Fatal("auto mode must probe immediately at start")
	}
	c.onProbeResult(true, t0)
	if c.state != stateUDP {
		t.Fatalf("echo ok -> UDP, got %v", c.state)
	}

	c2 := newTestController(ModeAuto)
	c2.tick(t0)
	c2.onProbeResult(false, t0)
	if c2.state != stateWS {
		t.Fatalf("echo failed -> WS, got %v", c2.state)
	}
}

func TestControllerAutoProbesWhileOnWSWithBackoff(t *testing.T) {
	tm := defaultTimings()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(false, t0)

	if c.tick(t0.Add(tm.probeMin - time.Second)) {
		t.Fatal("probe too early")
	}
	now := t0.Add(tm.probeMin)
	if !c.tick(now) {
		t.Fatal("expected probe after probeMin")
	}
	c.onProbeResult(false, now)
	if c.tick(now.Add(tm.probeMin)) {
		t.Fatal("backoff should have doubled")
	}
	if !c.tick(now.Add(2 * tm.probeMin)) {
		t.Fatal("expected probe after doubled backoff")
	}

	// backoff is capped
	for i := 0; i < 20; i++ {
		c.onProbeResult(false, now)
	}
	if c.backoff != tm.probeMax {
		t.Fatalf("backoff %v not capped at %v", c.backoff, tm.probeMax)
	}
}

func TestControllerAutoNoProbeWhileOnUDP(t *testing.T) {
	c := newTestController(ModeAuto)
	c.tick(t0)
	c.onProbeResult(true, t0)
	if c.tick(t0.Add(time.Hour)) {
		t.Fatal("no periodic probing while on UDP")
	}
}

func TestControllerHandshakeTimeoutFallsBack(t *testing.T) {
	tm := defaultTimings()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(true, t0)

	c.onHandshakeSent(t0)
	c.onHandshakeSent(t0.Add(5 * time.Second)) // retries must not reset the timer
	c.tick(t0.Add(tm.handshakeTimeout - time.Second))
	if c.state != stateUDP {
		t.Fatal("fell back too early")
	}
	c.tick(t0.Add(tm.handshakeTimeout))
	if c.state != stateWS {
		t.Fatal("expected fallback after handshake timeout")
	}
}

func TestControllerHandshakeResponseClearsTimer(t *testing.T) {
	tm := defaultTimings()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(true, t0)
	c.onHandshakeSent(t0)
	c.onServerRecv(true, t0.Add(time.Second))
	c.tick(t0.Add(time.Hour))
	if c.state != stateUDP {
		t.Fatal("handshake response must clear the timer")
	}
}

func switchedBack(t *testing.T, tm timings) (*controller, time.Time) {
	t.Helper()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(false, t0)
	now := t0.Add(tm.probeMin)
	if !c.tick(now) {
		t.Fatal("expected probe")
	}
	c.onProbeResult(true, now)
	if c.state != stateUDP {
		t.Fatal("echo ok while on WS -> UDP")
	}
	return c, now
}

func TestControllerSwitchBackConfirmedByHandshake(t *testing.T) {
	tm := defaultTimings()
	c, now := switchedBack(t, tm)
	c.growBackoff()
	c.onHandshakeSent(now)
	c.onServerRecv(true, now.Add(time.Second))
	c.tick(now.Add(time.Hour))
	if c.state != stateUDP {
		t.Fatal("confirmed switch-back must stay on UDP")
	}
	if c.backoff != tm.probeMin {
		t.Fatalf("confirmed switch-back resets backoff, got %v", c.backoff)
	}
}

func TestControllerSwitchBackRevertsWithBackoffOnHandshakeTimeout(t *testing.T) {
	tm := defaultTimings()
	c, now := switchedBack(t, tm)
	c.onHandshakeSent(now)
	c.tick(now.Add(tm.handshakeTimeout))
	if c.state != stateWS {
		t.Fatal("unconfirmed switch-back must revert to WS")
	}
	if c.backoff <= tm.probeMin {
		t.Fatalf("revert after switch-back must keep backing off, got %v", c.backoff)
	}
}

func TestControllerInitialHandshakeTimeoutUsesMinBackoff(t *testing.T) {
	tm := defaultTimings()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(true, t0)
	c.onHandshakeSent(t0)
	c.tick(t0.Add(tm.handshakeTimeout))
	if c.state != stateWS || c.backoff != tm.probeMin {
		t.Fatalf("state=%v backoff=%v", c.state, c.backoff)
	}
}

func TestControllerSwitchBackWithoutVerifierStaysOnUDP(t *testing.T) {
	tm := defaultTimings()
	c := newController(ModeAuto, tm)
	c.tick(t0)
	c.onProbeResult(false, t0)
	now := t0.Add(tm.probeMin)
	c.tick(now)
	c.onProbeResult(true, now)
	c.tick(now.Add(time.Hour))
	if c.state != stateUDP {
		t.Fatal("without handshake evidence, echo alone decides")
	}
}

func TestControllerNetworkChangeReprobes(t *testing.T) {
	c := newTestController(ModeAuto)
	c.tick(t0)
	c.onProbeResult(true, t0)
	c.networkChanged(t0.Add(time.Minute))
	if !c.tick(t0.Add(time.Minute)) {
		t.Fatal("network change must trigger an immediate probe")
	}
	c.onProbeResult(false, t0.Add(time.Minute))
	if c.state != stateWS {
		t.Fatal("failed re-probe while on UDP -> WS")
	}
}

func TestControllerProbeResultIgnoredWhenNotRequested(t *testing.T) {
	c := newTestController(ModeTCP)
	c.onProbeResult(true, t0)
	if c.state != stateWS {
		t.Fatal("tcp mode ignores probe results")
	}
}
