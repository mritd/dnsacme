//go:build duckdns || !slim

package main

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/duckdns"
)

func DuckDNS(conf *Config) (certmagic.ACMEDNSProvider, error) {
	return &duckdns.Provider{
		APIToken:       conf.DNSConfig[ENV_DUCKDNS_API_TOKEN],
		OverrideDomain: conf.DNSConfig[ENV_DUCKDNS_OVERRIDE_DOMAIN],
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_DUCKDNS] = DuckDNS
}
