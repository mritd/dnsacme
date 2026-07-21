//go:build godaddy || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/godaddy"
)

// newGoDaddy validates the API token and constructs its libdns provider.
func newGoDaddy(config map[string]string) (certmagic.DNSProvider, error) {
	if token, ok := config[GoDaddyAPIToken]; ok {
		return &godaddy.Provider{APIToken: token}, nil
	}
	return nil, errors.New("failed to get Godaddy API Token")
}

// init registers GoDaddy when its build constraint is satisfied.
func init() {
	register(Definition{Name: GoDaddy, Label: "GoDaddy", Fields: []Field{
		{Key: GoDaddyAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "key:secret"},
	}}, newGoDaddy)
}
