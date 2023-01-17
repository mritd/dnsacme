//go:build godaddy || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/godaddy"
)

func Godaddy(conf *Config) (certmagic.ACMEDNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_GODADDY_API_TOKEN]; ok {
		return &godaddy.Provider{APIToken: val}, nil
	}
	return nil, errors.New("failed to get Godaddy API Token")
}

func init() {
	providerFn[DNS_PROVIDER_GODADDY] = Godaddy
}
