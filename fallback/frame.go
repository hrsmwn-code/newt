package fallback

import (
	"encoding/binary"
	"errors"
)

// Wire protocol (fallback-relay.v1): every binary WebSocket message carries
// exactly one UDP datagram, prefixed with a 2-byte big-endian port.
//
//	client -> relay: port = destination port on the server (e.g. 51820, 21820)
//	relay -> client: port = source port on the server the datagram came from
const (
	Subprotocol    = "fallback-relay.v1"
	frameHeaderLen = 2
)

var errShortFrame = errors.New("fallback: frame too short")

// appendFrame appends a frame for payload to dst and returns it.
func appendFrame(dst []byte, port uint16, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, port)
	return append(dst, payload...)
}

// parseFrame splits a frame into port and payload. payload aliases b.
// Frames with an empty payload are rejected.
func parseFrame(b []byte) (uint16, []byte, error) {
	if len(b) <= frameHeaderLen {
		return 0, nil, errShortFrame
	}
	return binary.BigEndian.Uint16(b), b[frameHeaderLen:], nil
}
