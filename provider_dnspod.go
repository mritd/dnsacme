//go:build dnspod || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/dnspod"
)

func DNSPod(conf *Config) (certmagic.DNSProvider, error) {
	if val, ok := conf.DNSConfig[ENV_DNSPOD_API_TOKEN]; ok {
		return &dnspod.Provider{APIToken: val}, nil
	}
	return nil, errors.New("failed to get Vultr API Token")
}

func init() {
	providerFn[DNS_PROVIDER_DNSPOD] = DNSPod
}
