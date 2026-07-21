//go:build azure || !slim

package provider

import (
	"github.com/caddyserver/certmagic"
	"github.com/libdns/azure"
)

// newAzure maps Azure DNS credentials to its libdns provider.
func newAzure(config map[string]string) (certmagic.DNSProvider, error) {
	return &azure.Provider{
		TenantId: config[AzureTenantID], ClientId: config[AzureClientID], ClientSecret: config[AzureClientSecret],
		SubscriptionId: config[AzureSubscriptionID], ResourceGroupName: config[AzureResourceGroupName],
	}, nil
}

// init registers Azure DNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: Azure, Label: "Azure DNS", Fields: []Field{
		{Key: AzureTenantID, Label: "Tenant ID", Required: true},
		{Key: AzureClientID, Label: "Client ID", Required: true},
		{Key: AzureClientSecret, Label: "Client Secret", Secret: true, Required: true},
		{Key: AzureSubscriptionID, Label: "Subscription ID", Required: true},
		{Key: AzureResourceGroupName, Label: "Resource Group", Required: true},
	}}, newAzure)
}
