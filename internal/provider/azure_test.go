//go:build azure || !slim

package provider

import (
	"testing"

	"github.com/libdns/azure"
)

func TestNewAzure_MapsCredentials(t *testing.T) {
	got, err := New(Azure, map[string]string{
		AzureTenantID: "tenant", AzureClientID: "client", AzureClientSecret: "secret",
		AzureSubscriptionID: "subscription", AzureResourceGroupName: "group",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*azure.Provider)
	if !ok {
		t.Fatalf("New returned %T", got)
	}
	if provider.TenantId != "tenant" || provider.ClientId != "client" || provider.ClientSecret != "secret" ||
		provider.SubscriptionId != "subscription" || provider.ResourceGroupName != "group" {
		t.Fatalf("unexpected provider: %#v", provider)
	}
}
