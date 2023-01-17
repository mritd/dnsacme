//go:build vultr || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/vultr"
)

func Vultr(conf *Config) (certmagic.ACMEDNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_VULTR_API_TOKEN]; ok {
		return &vultr.Provider{APIToken: val}, nil
	}
	return nil, errors.New("failed to get Vultr API Token")
}

func init() {
	providerFn[DNS_PROVIDER_VULTR] = Vultr
}
