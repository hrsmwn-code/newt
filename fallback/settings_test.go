package fallback

import (
	"flag"
	"testing"
)

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{
		"":       ModeAuto,
		"auto":   ModeAuto,
		"TCP":    ModeTCP,
		" udp  ": ModeUDP,
	}
	for in, want := range cases {
		got, err := ParseMode(in)
		if err != nil {
			t.Fatalf("ParseMode(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseMode(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseMode("quic"); err == nil {
		t.Fatal("ParseMode(\"quic\") should fail")
	}
}

func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.Mode != ModeAuto || s.RelayPath != "/fallback-relay" || s.EchoPort != 21821 {
		t.Fatalf("unexpected defaults: %+v", s)
	}
}

func TestApplyEnvOverridesDefaults(t *testing.T) {
	t.Setenv("PANGOLIN_TRANSPORT", "tcp")
	t.Setenv("FALLBACK_RELAY_PATH", "/other")
	t.Setenv("FALLBACK_ECHO_PORT", "4000")
	s := DefaultSettings()
	s.ApplyEnv()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if s.Mode != ModeTCP || s.RelayPath != "/other" || s.EchoPort != 4000 {
		t.Fatalf("env not applied: %+v", s)
	}
}

func TestApplyFile(t *testing.T) {
	mode, path, port := "udp", "/p", 1234
	s := DefaultSettings()
	s.ApplyFile(FileSettings{Transport: &mode, FallbackRelayPath: &path, FallbackEchoPort: &port})
	if s.Mode != ModeUDP || s.RelayPath != "/p" || s.EchoPort != 1234 {
		t.Fatalf("file not applied: %+v", s)
	}
}

func TestRegisterFlags(t *testing.T) {
	s := DefaultSettings()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	s.RegisterFlags(fs)
	if err := fs.Parse([]string{"--transport", "tcp", "--fallback-relay-path", "/x", "--fallback-echo-port", "9"}); err != nil {
		t.Fatal(err)
	}
	if s.Mode != ModeTCP || s.RelayPath != "/x" || s.EchoPort != 9 {
		t.Fatalf("flags not applied: %+v", s)
	}
}

func TestRegisterFlagsRejectsBadMode(t *testing.T) {
	s := DefaultSettings()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(discard{})
	s.RegisterFlags(fs)
	if err := fs.Parse([]string{"--transport", "quic"}); err == nil {
		t.Fatal("expected error for bad transport")
	}
}

func TestValidate(t *testing.T) {
	bad := []Settings{
		{Mode: "nope", RelayPath: "/x", EchoPort: 1},
		{Mode: ModeAuto, RelayPath: "x", EchoPort: 1},
		{Mode: ModeAuto, RelayPath: "/x", EchoPort: -1},
		{Mode: ModeAuto, RelayPath: "/x", EchoPort: 70000},
	}
	for _, s := range bad {
		if err := s.Validate(); err == nil {
			t.Fatalf("Validate(%+v) should fail", s)
		}
	}
	empty := Settings{}
	if err := empty.Validate(); err != nil {
		t.Fatalf("zero Settings should validate (filled with defaults): %v", err)
	}
	if empty != DefaultSettings() {
		t.Fatalf("zero Settings should be filled with defaults, got %+v", empty)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
