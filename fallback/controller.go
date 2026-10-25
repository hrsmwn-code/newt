package fallback

import "time"

// pathState is which path datagrams to the server currently take.
type pathState int

const (
	// stateUndecided: auto mode before the first echo probe completed.
	// Server-bound datagrams are held (see Transport) until a decision.
	stateUndecided pathState = iota
	stateUDP
	stateWS
)

func (s pathState) String() string {
	switch s {
	case stateUDP:
		return "udp"
	case stateWS:
		return "tcp"
	}
	return "undecided"
}

type timings struct {
	probeTimeout     time.Duration // how long one echo probe round waits
	probeMin         time.Duration // first re-probe interval while on WS
	probeMax         time.Duration // cap for re-probe backoff
	handshakeTimeout time.Duration // no handshake response on UDP -> fall back
	// once a handshake has succeeded, tolerate ~3 lost handshakes (wireguard
	// retries every 5 s) before treating UDP as broken
	establishedHandshakeTimeout time.Duration
}

func defaultTimings() timings {
	return timings{
		probeTimeout:     3 * time.Second,
		probeMin:         30 * time.Second,
		probeMax:         10 * time.Minute,
		handshakeTimeout: 10 * time.Second,

		establishedHandshakeTimeout: 20 * time.Second,
	}
}

// controller is the pure (clock-injected) transport decision state machine.
// It is not safe for concurrent use; Transport serialises access.
type controller struct {
	mode Mode
	tm   timings

	state pathState

	// probe scheduling (auto only)
	probeDue      bool
	probeInFlight bool
	nextProbe     time.Time
	backoff       time.Duration

	// handshake watchdog: first unanswered handshake initiation sent over UDP
	handshakePending   bool
	handshakeFirstSent time.Time
	established        bool // a handshake response arrived over UDP since the last switch

	// probation: we switched back to UDP because the echo worked, but no
	// handshake has confirmed it yet. A handshake timeout during probation
	// keeps growing the backoff instead of resetting it, so a network where
	// only the echo port is open doesn't flap every 30 s.
	probation bool

	// set by state changes; consumed by Transport for logging
	lastReason string
}

func newController(mode Mode, tm timings) *controller {
	c := &controller{mode: mode, tm: tm, backoff: tm.probeMin}
	switch mode {
	case ModeTCP:
		c.state = stateWS
	case ModeUDP:
		c.state = stateUDP
	default:
		c.state = stateUndecided
		c.probeDue = true
	}
	return c
}

func (c *controller) setState(s pathState, reason string) {
	if c.state == s {
		return
	}
	c.state = s
	c.lastReason = reason
	c.handshakePending = false
	c.probation = false
	c.established = false
}

// tick advances timers. It returns true when the caller should start an echo
// probe now (it then must call onProbeResult).
func (c *controller) tick(now time.Time) bool {
	if c.mode != ModeAuto {
		return false
	}

	timeout := c.tm.handshakeTimeout
	if c.established && c.tm.establishedHandshakeTimeout > timeout {
		timeout = c.tm.establishedHandshakeTimeout
	}
	if c.state == stateUDP && c.handshakePending && !now.Before(c.handshakeFirstSent.Add(timeout)) {
		onProbation := c.probation
		c.setState(stateWS, "no WireGuard handshake response from the server over UDP")
		if onProbation {
			c.growBackoff()
		} else {
			c.backoff = c.tm.probeMin
		}
		c.scheduleProbe(now)
	}

	if c.probeInFlight {
		return false
	}
	if c.probeDue || (c.state == stateWS && !c.nextProbe.IsZero() && !now.Before(c.nextProbe)) {
		c.probeDue = false
		c.probeInFlight = true
		return true
	}
	return false
}

func (c *controller) scheduleProbe(now time.Time) {
	c.nextProbe = now.Add(c.backoff)
}

func (c *controller) growBackoff() {
	c.backoff *= 2
	if c.backoff > c.tm.probeMax {
		c.backoff = c.tm.probeMax
	}
}

// onProbeResult records the outcome of an echo probe started via tick.
func (c *controller) onProbeResult(ok bool, now time.Time) {
	if c.mode != ModeAuto {
		return
	}
	c.probeInFlight = false

	switch c.state {
	case stateUndecided:
		if ok {
			c.setState(stateUDP, "UDP echo from the server succeeded")
		} else {
			c.setState(stateWS, "no UDP echo from the server")
			c.scheduleProbe(now)
		}
	case stateUDP:
		// only reached after networkChanged
		if !ok {
			c.setState(stateWS, "no UDP echo from the server after a network change")
			c.backoff = c.tm.probeMin
			c.scheduleProbe(now)
		}
	case stateWS:
		if ok {
			c.setState(stateUDP, "UDP echo from the server succeeded again")
			c.probation = true
		} else {
			c.growBackoff()
			c.scheduleProbe(now)
		}
	}
}

// onHandshakeSent records a WireGuard handshake initiation sent to the
// server over UDP. Only call it for a path whose WireGuard peer *is* the
// server (the Newt main tunnel); relayed peers can be down for unrelated
// reasons.
func (c *controller) onHandshakeSent(now time.Time) {
	if c.mode != ModeAuto || c.state != stateUDP || c.handshakePending {
		return
	}
	c.handshakePending = true
	c.handshakeFirstSent = now
}

// onServerRecv records a datagram received from the server over UDP.
// handshakeResponse is true for a WireGuard handshake response.
func (c *controller) onServerRecv(handshakeResponse bool, now time.Time) {
	if c.state != stateUDP {
		return
	}
	if handshakeResponse {
		c.handshakePending = false
		c.established = true
		if c.probation {
			c.probation = false
			c.backoff = c.tm.probeMin
		}
	}
}

// networkChanged requests an immediate re-probe (auto mode only).
func (c *controller) networkChanged(now time.Time) {
	if c.mode != ModeAuto {
		return
	}
	c.probeDue = true
	c.backoff = c.tm.probeMin
}
