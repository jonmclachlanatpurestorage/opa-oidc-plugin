package main

import (
	"fmt"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/runtime"
	"github.com/purestorage/opa-oidc-plugin/internal"
	"os"
)

// Factory defines the interface OPA uses to instantiate a plugin.
type Factory struct{}

// New returns the object initialized with a valid plugin configuration.
func (Factory) New(m *plugins.Manager, config interface{}) plugins.Plugin {
	return internal.New(m, config.(*internal.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (Factory) Validate(m *plugins.Manager, config []byte) (interface{}, error) {
	return internal.Validate(m, config)
}

func main() {
	runtime.RegisterPlugin("opa-oidc-plugin", Factory{})

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
