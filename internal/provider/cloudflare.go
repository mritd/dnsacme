//go:build cloudflare || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// newCloudflare validates the API token and constructs its libdns provider.
func newCloudflare(config map[string]string) (certmagic.DNSProvider, error) {
	if token, ok := config[CloudflareAPIToken]; ok {
		return &cloudflare.Provider{APIToken: token}, nil
	}
	return nil, errors.New("failed to get Cloudflare API Token")
}

// init registers Cloudflare when its build constraint is satisfied.
func init() {
	register(Definition{Name: Cloudflare, Label: "Cloudflare", Fields: []Field{
		{Key: CloudflareAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "Zone DNS edit token"},
	}}, newCloudflare)
}
