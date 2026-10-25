package fallback

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("hello wireguard")
	f := appendFrame(nil, 51820, payload)
	if len(f) != len(payload)+frameHeaderLen {
		t.Fatalf("frame length %d", len(f))
	}
	port, got, err := parseFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	if port != 51820 || !bytes.Equal(got, payload) {
		t.Fatalf("got port=%d payload=%q", port, got)
	}
}

func TestFrameCopiesPayload(t *testing.T) {
	payload := []byte("abc")
	f := appendFrame(nil, 1, payload)
	payload[0] = 'z'
	_, got, _ := parseFrame(f)
	if got[0] != 'a' {
		t.Fatal("appendFrame must copy the payload")
	}
}

func TestParseFrameRejectsShort(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, {1, 2}} {
		if _, _, err := parseFrame(b); err == nil {
			t.Fatalf("parseFrame(%v) should fail", b)
		}
	}
}
