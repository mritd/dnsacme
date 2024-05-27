//go:build azure || !slim

package main

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/azure"
)

func Azure(conf *Config) (certmagic.DNSProvider, error) {
	return &azure.Provider{
		TenantId:          conf.DNSConfig[ENV_AZURE_TENANTID],
		ClientId:          conf.DNSConfig[ENV_AZURE_CLIENTID],
		ClientSecret:      conf.DNSConfig[ENV_AZURE_CLIENTSECRET],
		SubscriptionId:    conf.DNSConfig[ENV_AZURE_SUBSCRIPTIONID],
		ResourceGroupName: conf.DNSConfig[ENV_AZURE_RESOURCEGROUPNAME],
	}, nil
}

func init() {
	providerFn[DNS_PROVIDER_AZURE] = Azure
}
