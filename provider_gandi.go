//go:build gandi || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/gandi"
)

func Gandi(conf *Config) (certmagic.DNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_GANDI_API_TOKEN]; ok {
		return &gandi.Provider{BearerToken: val}, nil
	}
	return nil, errors.New("failed to get Gandi API Token")
}

func init() {
	providerFn[DNS_PROVIDER_GANDI] = Gandi
}
