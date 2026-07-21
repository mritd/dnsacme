//go:build !slim

package provider

import (
	"reflect"
	"testing"
)

func TestCatalog_DefaultBuildContainsAllProviders(t *testing.T) {
	wantNames := []string{AliDNS, Azure, Cloudflare, DuckDNS, Gandi, GoDaddy, HuaweiCloud, TencentCloud}
	if got := Names(); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("Names() = %v, want %v", got, wantNames)
	}

	wantDefinitions := []string{Cloudflare, AliDNS, Azure, DuckDNS, Gandi, GoDaddy, HuaweiCloud, TencentCloud}
	definitions := Definitions()
	gotDefinitions := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		gotDefinitions = append(gotDefinitions, definition.Name)
	}
	if !reflect.DeepEqual(gotDefinitions, wantDefinitions) {
		t.Fatalf("Definitions order = %v, want %v", gotDefinitions, wantDefinitions)
	}
}

func TestCatalog_DefaultBuildConstructsEveryProvider(t *testing.T) {
	config := map[string]string{
		AliDNSAccessKeyID: "ali-id", AliDNSAccessKeySecret: "ali-secret", AliDNSRegionID: "cn-hangzhou",
		AzureTenantID: "tenant", AzureClientID: "client", AzureClientSecret: "secret",
		AzureSubscriptionID: "subscription", AzureResourceGroupName: "group",
		CloudflareAPIToken: "cloudflare-token", DuckDNSAPIToken: "duck-token",
		DuckDNSOverrideDomain: "duck.example.com", GandiAPIToken: "gandi-token", GoDaddyAPIToken: "godaddy-token",
		HuaweiCloudAccessKeyID: "huawei-id", HuaweiCloudAccessKeySecret: "huawei-secret", HuaweiCloudRegionID: "cn-south-1",
		TencentCloudAccessKeyID: "tencent-id", TencentCloudAccessKeySecret: "tencent-secret",
	}
	for _, definition := range Definitions() {
		t.Run(definition.Name, func(t *testing.T) {
			if _, err := New(definition.Name, config); err != nil {
				t.Fatalf("New(%q) returned error: %v", definition.Name, err)
			}
		})
	}
}
