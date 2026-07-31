//go:build hetznercloud || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/hetzner/v2"
)

// newHetznerCloud validates the API token and constructs its libdns provider.
func newHetznerCloud(config map[string]string) (certmagic.DNSProvider, error) {
	if token, ok := config[HetznerCloudAPIToken]; ok {
		return &hetzner.Provider{APIToken: token}, nil
	}
	return nil, errors.New("failed to get Hetzner Cloud API Token")
}

// init registers Hetzner Cloud when its build constraint is satisfied.
func init() {
	register(Definition{Name: HetznerCloud, Label: "Hetzner Cloud", Fields: []Field{
		{Key: HetznerCloudAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "Hetzner Cloud API token"},
	}}, newHetznerCloud)
}
