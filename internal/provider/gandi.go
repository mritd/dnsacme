//go:build gandi || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/gandi"
)

// newGandi validates the API token and constructs its libdns provider.
func newGandi(config map[string]string) (certmagic.DNSProvider, error) {
	if token, ok := config[GandiAPIToken]; ok {
		return &gandi.Provider{BearerToken: token}, nil
	}
	return nil, errors.New("failed to get Gandi API Token")
}

// init registers Gandi when its build constraint is satisfied.
func init() {
	register(Definition{Name: Gandi, Label: "Gandi", Fields: []Field{
		{Key: GandiAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "Personal Access Token"},
	}}, newGandi)
}
