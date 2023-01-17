//go:build namedotcom || !slim

package main

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/namedotcom"
)

func NameDotCom(conf *Config) (certmagic.ACMEDNSProvider, error) {
	return &namedotcom.Provider{
		Token:  conf.DNSConfig[ENV_NAMEDOTCOM_TOKEN],
		User:   conf.DNSConfig[ENV_NAMEDOTCOM_USER],
		Server: conf.DNSConfig[ENV_NAMEDOTCOM_SERVER],
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_NAMEDOTCOM] = NameDotCom
}
