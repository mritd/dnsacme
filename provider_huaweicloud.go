//go:build huaweicloud || !slim

package main

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/huaweicloud"
)

func HuaweiCloudDNS(conf *Config) (certmagic.DNSProvider, error) {
	accessKeyId, ok := conf.DNSConfig[ENV_HUAWEICLOUD_ACCKEYID]
	if !ok {
		return nil, errors.New("failed to get HuaweiCloud AccessKeyID")
	}
	secretAccessKey, ok := conf.DNSConfig[ENV_HUAWEICLOUD_ACCKEYSECRET]
	if !ok {
		return nil, errors.New("failed to get HuaweiCloud AccessKeySecret")
	}

	return &huaweicloud.Provider{
		AccessKeyId:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		RegionId:        conf.DNSConfig[ENV_HUAWEICLOUD_REGIONID],
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_HUAWEICLOUD] = HuaweiCloudDNS
}
