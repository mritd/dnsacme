//go:build tencentcloud || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/tencentcloud"
)

func TencentCloudDns(conf *Config) (certmagic.DNSProvider, error) {
	secretId, ok := conf.DNSConfig[ENV_TENCENTCLOUD_ACCKEYID]
	if !ok {
		return nil, errors.New("failed to get TencentCloud AccessKeyID")
	}
	secretKey, ok := conf.DNSConfig[ENV_TENCENTCLOUD_ACCKEYSECRET]
	if !ok {
		return nil, errors.New("failed to get TencentCloud AccessKeySecret")
	}

	return &tencentcloud.Provider{
		SecretId:  secretId,
		SecretKey: secretKey,
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_TENCENTCLOUD] = TencentCloudDns
}
