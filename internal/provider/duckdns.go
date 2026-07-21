//go:build duckdns || !slim

package provider

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
)

// newDuckDNS maps Duck DNS credentials to its libdns provider.
func newDuckDNS(config map[string]string) (certmagic.DNSProvider, error) {
	return &duckdns.Provider{APIToken: config[DuckDNSAPIToken], OverrideDomain: config[DuckDNSOverrideDomain]}, nil
}

// init registers Duck DNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: DuckDNS, Label: "Duck DNS", Fields: []Field{
		{Key: DuckDNSAPIToken, Label: "API Token", Secret: true, Required: true, Placeholder: "duckdns token"},
		{Key: DuckDNSOverrideDomain, Label: "Override Domain"},
	}}, newDuckDNS)
}
