package newt

// Fork-only: wiring for the TCP 443 fallback transport. Upstream files only
// call setupFallback / fallbackCredentials / fallbackWrapBind.

import (
	"golang.zx2c4.com/wireguard/conn"

	"github.com/fosrl/newt/fallback"
	"github.com/fosrl/newt/logger"
)

// setupFallback creates and installs the process-wide fallback transport.
// In udp mode nothing is installed, so behaviour is exactly upstream.
func (n *Newt) setupFallback() {
	s := n.config.Fallback
	if err := s.Validate(); err != nil {
		logger.Error("fallback: invalid settings, using upstream UDP behaviour: %v", err)
		return
	}
	if s.Mode == fallback.ModeUDP {
		return
	}
	var opts []fallback.Option
	if tlsCfg, err := n.client.FallbackTLSConfig(); err != nil {
		logger.Error("fallback: TLS setup failed: %v", err)
	} else if tlsCfg != nil {
		opts = append(opts, fallback.WithTLSConfig(tlsCfg))
	}
	t, err := fallback.New(s, n.config.Endpoint, opts...)
	if err != nil {
		logger.Error("fallback: disabled: %v", err)
		return
	}
	t.OnSwitch(func(relay bool) {
		// Re-register quickly on the new path: hole punches tell Gerbil and
		// Pangolin our new address.
		if n.wgService != nil {
			n.wgService.TriggerFallbackHolePunch()
		}
	})
	fallback.Install(t)
}

// fallbackCredentials passes the control-channel session token to the
// fallback transport.
func (n *Newt) fallbackCredentials(token string) {
	fallback.Default().SetCredentials(fallback.Credentials{
		ClientType: "newt",
		ID:         n.config.ID,
		Token:      token,
	})
}

// fallbackWrapBind wraps the main tunnel bind and registers the Gerbil
// endpoint host as a server address.
func (n *Newt) fallbackWrapBind(b conn.Bind, endpoint string) conn.Bind {
	t := fallback.Default()
	t.AddServerHost(endpoint)
	return t.WrapBind(b)
}

func (n *Newt) closeFallback() {
	if t := fallback.Default(); t != nil {
		fallback.Install(nil)
		t.Close()
	}
}
