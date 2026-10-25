package newtconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fosrl/newt/fallback"
)

func clearFallbackEnv(t *testing.T) {
	t.Helper()
	clearNewtEnv(t)
	for _, k := range []string{fallback.EnvTransport, fallback.EnvRelayPath, fallback.EnvEchoPort} {
		t.Setenv(k, "")
	}
}

func TestLoadFallback_Defaults(t *testing.T) {
	clearFallbackEnv(t)
	cfg, err := Load(Options{Args: []string{"--config-file", filepath.Join(t.TempDir(), "missing.json")}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fallback != fallback.DefaultSettings() {
		t.Fatalf("got %+v", cfg.Fallback)
	}
}

func TestLoadFallback_Precedence(t *testing.T) {
	clearFallbackEnv(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"transport":"udp","fallbackRelayPath":"/from-file","fallbackEchoPort":1111}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(Options{Args: []string{"--config-file", path}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fallback.Mode != fallback.ModeUDP || cfg.Fallback.RelayPath != "/from-file" || cfg.Fallback.EchoPort != 1111 {
		t.Fatalf("file not applied: %+v", cfg.Fallback)
	}

	t.Setenv(fallback.EnvTransport, "tcp")
	cfg, err = Load(Options{Args: []string{"--config-file", path}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fallback.Mode != fallback.ModeTCP || cfg.Fallback.RelayPath != "/from-file" {
		t.Fatalf("env must override file: %+v", cfg.Fallback)
	}

	cfg, err = Load(Options{Args: []string{"--config-file", path, "--transport", "auto", "--fallback-relay-path", "/cli"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Fallback.Mode != fallback.ModeAuto || cfg.Fallback.RelayPath != "/cli" {
		t.Fatalf("cli must override env: %+v", cfg.Fallback)
	}
}

func TestLoadFallback_InvalidEnv(t *testing.T) {
	clearFallbackEnv(t)
	t.Setenv(fallback.EnvTransport, "quic")
	if _, err := Load(Options{Args: []string{"--config-file", filepath.Join(t.TempDir(), "missing.json")}}); err == nil {
		t.Fatal("invalid PANGOLIN_TRANSPORT must be an error")
	}
}
