package main

import (
	"strings"
	"testing"

	"github.com/libdns/alidns"
	"github.com/libdns/azure"
	"github.com/libdns/cloudflare"
	"github.com/libdns/duckdns"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/libdns/huaweicloud"
	"github.com/libdns/tencentcloud"
)

func TestProviderConstructors(t *testing.T) {
	conf := &Config{DNSConfig: map[string]string{
		ENV_ALIDNS_ACCKEYID:           "ali-id",
		ENV_ALIDNS_ACCKEYSECRET:       "ali-secret",
		ENV_ALIDNS_REGIONID:           "cn-hangzhou",
		ENV_AZURE_TENANTID:            "tenant",
		ENV_AZURE_CLIENTID:            "client",
		ENV_AZURE_CLIENTSECRET:        "secret",
		ENV_AZURE_SUBSCRIPTIONID:      "sub",
		ENV_AZURE_RESOURCEGROUPNAME:   "group",
		ENV_CLOUDFLARE_API_TOKEN:      "cf-token",
		ENV_DUCKDNS_API_TOKEN:         "duck-token",
		ENV_DUCKDNS_OVERRIDE_DOMAIN:   "duck.example.com",
		ENV_GANDI_API_TOKEN:           "gandi-token",
		ENV_GODADDY_API_TOKEN:         "godaddy-token",
		ENV_HUAWEICLOUD_ACCKEYID:      "hw-id",
		ENV_HUAWEICLOUD_ACCKEYSECRET:  "hw-secret",
		ENV_HUAWEICLOUD_REGIONID:      "cn-south-1",
		ENV_TENCENTCLOUD_ACCKEYID:     "tc-id",
		ENV_TENCENTCLOUD_ACCKEYSECRET: "tc-secret",
	}}

	t.Run("alidns", func(t *testing.T) {
		p, err := AliDNS(conf)
		if err != nil {
			t.Fatalf("AliDNS returned error: %v", err)
		}
		got := p.(*alidns.Provider)
		if got.AccessKeyID != "ali-id" || got.AccessKeySecret != "ali-secret" || got.RegionID != "cn-hangzhou" {
			t.Fatalf("unexpected AliDNS provider: %#v", got)
		}
	})

	t.Run("azure", func(t *testing.T) {
		p, err := Azure(conf)
		if err != nil {
			t.Fatalf("Azure returned error: %v", err)
		}
		got := p.(*azure.Provider)
		if got.TenantId != "tenant" || got.ClientId != "client" || got.ClientSecret != "secret" ||
			got.SubscriptionId != "sub" || got.ResourceGroupName != "group" {
			t.Fatalf("unexpected Azure provider: %#v", got)
		}
	})

	t.Run("cloudflare", func(t *testing.T) {
		p, err := Cloudflare(conf)
		if err != nil {
			t.Fatalf("Cloudflare returned error: %v", err)
		}
		got := p.(*cloudflare.Provider)
		if got.APIToken != "cf-token" {
			t.Fatalf("unexpected Cloudflare token: %q", got.APIToken)
		}
	})

	t.Run("duckdns", func(t *testing.T) {
		p, err := DuckDNS(conf)
		if err != nil {
			t.Fatalf("DuckDNS returned error: %v", err)
		}
		got := p.(*duckdns.Provider)
		if got.APIToken != "duck-token" || got.OverrideDomain != "duck.example.com" {
			t.Fatalf("unexpected DuckDNS provider: %#v", got)
		}
	})

	t.Run("gandi", func(t *testing.T) {
		p, err := Gandi(conf)
		if err != nil {
			t.Fatalf("Gandi returned error: %v", err)
		}
		if got := p.(*gandi.Provider); got.BearerToken != "gandi-token" {
			t.Fatalf("unexpected Gandi provider: %#v", got)
		}
	})

	t.Run("godaddy", func(t *testing.T) {
		p, err := Godaddy(conf)
		if err != nil {
			t.Fatalf("Godaddy returned error: %v", err)
		}
		if got := p.(*godaddy.Provider); got.APIToken != "godaddy-token" {
			t.Fatalf("unexpected Godaddy provider: %#v", got)
		}
	})

	t.Run("huaweicloud", func(t *testing.T) {
		p, err := HuaweiCloudDNS(conf)
		if err != nil {
			t.Fatalf("HuaweiCloudDNS returned error: %v", err)
		}
		got := p.(*huaweicloud.Provider)
		if got.AccessKeyId != "hw-id" || got.SecretAccessKey != "hw-secret" || got.RegionId != "cn-south-1" {
			t.Fatalf("unexpected HuaweiCloud provider: %#v", got)
		}
	})

	t.Run("tencentcloud", func(t *testing.T) {
		p, err := TencentCloudDns(conf)
		if err != nil {
			t.Fatalf("TencentCloudDns returned error: %v", err)
		}
		got := p.(*tencentcloud.Provider)
		if got.SecretId != "tc-id" || got.SecretKey != "tc-secret" {
			t.Fatalf("unexpected TencentCloud provider: %#v", got)
		}
	})
}

func TestProviderConstructorErrors(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*Config) (any, error)
		want string
	}{
		{name: "alidns key id", fn: func(c *Config) (any, error) { return AliDNS(c) }, want: "AccessKeyID"},
		{name: "cloudflare token", fn: func(c *Config) (any, error) { return Cloudflare(c) }, want: "Cloudflare API Token"},
		{name: "gandi token", fn: func(c *Config) (any, error) { return Gandi(c) }, want: "Gandi API Token"},
		{name: "godaddy token", fn: func(c *Config) (any, error) { return Godaddy(c) }, want: "Godaddy API Token"},
		{name: "huaweicloud key id", fn: func(c *Config) (any, error) { return HuaweiCloudDNS(c) }, want: "HuaweiCloud AccessKeyID"},
		{name: "tencentcloud key id", fn: func(c *Config) (any, error) { return TencentCloudDns(c) }, want: "TencentCloud AccessKeyID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(&Config{DNSConfig: map[string]string{}})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestTwoPartProviderConstructorErrors(t *testing.T) {
	_, err := AliDNS(&Config{DNSConfig: map[string]string{ENV_ALIDNS_ACCKEYID: "id"}})
	if err == nil || !strings.Contains(err.Error(), "AccessKeySecret") {
		t.Fatalf("expected AliDNS secret error, got %v", err)
	}

	_, err = HuaweiCloudDNS(&Config{DNSConfig: map[string]string{ENV_HUAWEICLOUD_ACCKEYID: "id"}})
	if err == nil || !strings.Contains(err.Error(), "AccessKeySecret") {
		t.Fatalf("expected HuaweiCloud secret error, got %v", err)
	}

	_, err = TencentCloudDns(&Config{DNSConfig: map[string]string{ENV_TENCENTCLOUD_ACCKEYID: "id"}})
	if err == nil || !strings.Contains(err.Error(), "AccessKeySecret") {
		t.Fatalf("expected TencentCloud secret error, got %v", err)
	}
}

func TestProviderRegistryExcludesRemovedProviders(t *testing.T) {
	for _, removed := range []string{"dnspod", "namedotcom", "vultr"} {
		if _, ok := providerFn[removed]; ok {
			t.Fatalf("removed provider %q is still registered", removed)
		}
	}
	if _, ok := providerFn[DNS_PROVIDER_CLOUDFLARE]; !ok {
		t.Fatal("cloudflare provider is not registered")
	}
}
