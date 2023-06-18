//go:build namesilo || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/namesilo"
)

func NameSilo(conf *Config) (certmagic.ACMEDNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_NAMESILO_API_TOKEN]; ok {
		return &namesilo.Provider{APIToken: val}, nil
	}
	return nil, errors.New("failed to get NameSilo API Token")
}

func init() {
	providerFn[DNS_PROVIDER_NAMESILO] = NameSilo
}
