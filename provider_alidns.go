//go:build alidns || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
)

func AliDNS(conf *Config) (certmagic.ACMEDNSProvider, error) {
	accKeyID, ok := conf.DNSConfig[ENV_ALIDNS_ACCKEYID]
	if !ok {
		return nil, errors.New("failed to get AliDNS AccessKeyID")
	}
	accKeySecret, ok := conf.DNSConfig[ENV_ALIDNS_ACCKEYSECRET]
	if !ok {
		return nil, errors.New("failed to get AliDNS AccessKeySecret")
	}

	return &alidns.Provider{
		AccKeyID:     accKeyID,
		AccKeySecret: accKeySecret,
		RegionID:     conf.DNSConfig[ENV_ALIDNS_REGIONID],
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_ALIDNS] = AliDNS
}
