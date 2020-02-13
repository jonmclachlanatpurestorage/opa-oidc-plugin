package internal

import (
	"context"
	"github.com/open-policy-agent/opa/plugins"
)

// Config represents the plugin configuration.
type Config struct {
}

type OpaOidcPlugin struct {
	cfg                 Config
}

func (p *OpaOidcPlugin) Start(ctx context.Context) error {
	return nil
}

func (p *OpaOidcPlugin) Stop(ctx context.Context) {
}

func (p *OpaOidcPlugin) Reconfigure(ctx context.Context, config interface{}) {
	return
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {
	plugin := &OpaOidcPlugin{
		cfg:                 *cfg,
	}
	return plugin
}

// Validate receives a slice of bytes representing the plugin's
// configuration and returns a configuration value that can be used to
// instantiate the plugin.
func Validate(m *plugins.Manager, bs []byte) (*Config, error) {
	cfg := Config{}
	return &cfg, nil
}

