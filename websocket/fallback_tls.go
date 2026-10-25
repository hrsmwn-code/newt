package websocket

import (
	"crypto/tls"
	"os"
)

// FallbackTLSConfig returns the TLS configuration the fallback relay
// connection should use: the same mTLS / CA / SKIP_TLS_VERIFY settings as
// the control WebSocket. Returns nil for the default configuration.
// Fork-only (TCP 443 fallback).
func (c *Client) FallbackTLSConfig() (*tls.Config, error) {
	var cfg *tls.Config
	if c.tlsConfig.ClientCertFile != "" || c.tlsConfig.ClientKeyFile != "" || len(c.tlsConfig.CAFiles) > 0 || c.tlsConfig.PKCS12File != "" {
		var err error
		if cfg, err = c.setupTLS(); err != nil {
			return nil, err
		}
	}
	if os.Getenv("SKIP_TLS_VERIFY") == "true" {
		if cfg == nil {
			cfg = &tls.Config{}
		}
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}
