// Package fallback carries WireGuard / hole-punch UDP datagrams to the
// Pangolin server over a WebSocket on TCP 443 when UDP is blocked.
//
// This package is a fork-only addition (not part of upstream fosrl/newt).
// Upstream files only contain small hooks that call into it, so rebasing onto
// new upstream releases stays cheap.
package fallback

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Mode selects how datagrams to the Pangolin server are transported.
type Mode string

const (
	// ModeAuto uses UDP when it works, falls back to the WebSocket relay when
	// it doesn't, and keeps probing UDP while on the fallback.
	ModeAuto Mode = "auto"
	// ModeTCP always uses the WebSocket relay. No UDP is ever sent to the
	// server and UDP is never probed.
	ModeTCP Mode = "tcp"
	// ModeUDP never falls back (upstream behaviour).
	ModeUDP Mode = "udp"
)

const (
	DefaultRelayPath = "/fallback-relay"
	DefaultEchoPort  = 21821

	EnvTransport = "PANGOLIN_TRANSPORT"
	EnvRelayPath = "FALLBACK_RELAY_PATH"
	EnvEchoPort  = "FALLBACK_ECHO_PORT"
)

// ParseMode parses a transport mode; the empty string means ModeAuto.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeTCP:
		return ModeTCP, nil
	case ModeUDP:
		return ModeUDP, nil
	}
	return "", fmt.Errorf("invalid transport %q (want auto, tcp or udp)", s)
}

// Settings are the user-facing fallback settings.
type Settings struct {
	Mode      Mode
	RelayPath string
	EchoPort  int
}

// FileSettings is the JSON config-file representation of Settings.
type FileSettings struct {
	Transport         *string `json:"transport,omitempty"`
	FallbackRelayPath *string `json:"fallbackRelayPath,omitempty"`
	FallbackEchoPort  *int    `json:"fallbackEchoPort,omitempty"`
}

// DefaultSettings returns the defaults: auto mode, /fallback-relay, echo 21821.
func DefaultSettings() Settings {
	return Settings{Mode: ModeAuto, RelayPath: DefaultRelayPath, EchoPort: DefaultEchoPort}
}

// ApplyFile overlays values present in a config file.
func (s *Settings) ApplyFile(f FileSettings) {
	if f.Transport != nil {
		s.Mode = Mode(*f.Transport)
	}
	if f.FallbackRelayPath != nil {
		s.RelayPath = *f.FallbackRelayPath
	}
	if f.FallbackEchoPort != nil {
		s.EchoPort = *f.FallbackEchoPort
	}
}

// ApplyEnv overlays values from environment variables.
func (s *Settings) ApplyEnv() {
	if v := os.Getenv(EnvTransport); v != "" {
		s.Mode = Mode(v)
	}
	if v := os.Getenv(EnvRelayPath); v != "" {
		s.RelayPath = v
	}
	if v := os.Getenv(EnvEchoPort); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			s.EchoPort = p
		} else {
			s.EchoPort = -1 // rejected by Validate
		}
	}
}

// RegisterFlags registers --transport, --fallback-relay-path and
// --fallback-echo-port, defaulting to the current values.
func (s *Settings) RegisterFlags(fs *flag.FlagSet) {
	fs.Func("transport", fmt.Sprintf("Transport to the Pangolin server: auto, tcp or udp (default %q, env %s)", s.modeOrDefault(), EnvTransport), func(v string) error {
		m, err := ParseMode(v)
		if err != nil {
			return err
		}
		s.Mode = m
		return nil
	})
	fs.StringVar(&s.RelayPath, "fallback-relay-path", s.RelayPath, "URL path of the TCP 443 fallback relay (env "+EnvRelayPath+")")
	fs.IntVar(&s.EchoPort, "fallback-echo-port", s.EchoPort, "UDP echo port used to detect whether UDP works in auto mode (env "+EnvEchoPort+")")
}

func (s *Settings) modeOrDefault() Mode {
	if s.Mode == "" {
		return ModeAuto
	}
	return s.Mode
}

// Validate normalises the settings (empty values become defaults) and
// reports invalid values.
func (s *Settings) Validate() error {
	m, err := ParseMode(string(s.Mode))
	if err != nil {
		return err
	}
	s.Mode = m
	if s.RelayPath == "" {
		s.RelayPath = DefaultRelayPath
	}
	if !strings.HasPrefix(s.RelayPath, "/") {
		return fmt.Errorf("fallback relay path %q must start with /", s.RelayPath)
	}
	if s.EchoPort == 0 {
		s.EchoPort = DefaultEchoPort
	}
	if s.EchoPort < 1 || s.EchoPort > 65535 {
		return fmt.Errorf("fallback echo port %d must be 1-65535", s.EchoPort)
	}
	return nil
}
