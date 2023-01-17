//go:build cloudflare || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

func Cloudflare(conf *Config) (certmagic.ACMEDNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_CLOUDFLARE_API_TOKEN]; ok {
		return &cloudflare.Provider{APIToken: val}, nil
	}
	return nil, errors.New("failed to get Cloudflare API Token")
}

func init() {
	providerFn[DNS_PROVIDER_CLOUDFLARE] = Cloudflare
}
