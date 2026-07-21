//go:build alidns || !slim

package provider

import (
	"testing"

	"github.com/libdns/alidns"
)

func TestNewAliDNS_MapsCredentials(t *testing.T) {
	got, err := New("ALIDNS", map[string]string{
		AliDNSAccessKeyID: "id", AliDNSAccessKeySecret: "secret", AliDNSRegionID: "cn-hangzhou",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*alidns.Provider)
	if !ok {
		t.Fatalf("New returned %T", got)
	}
	if provider.AccessKeyID != "id" || provider.AccessKeySecret != "secret" || provider.RegionID != "cn-hangzhou" {
		t.Fatalf("unexpected provider: %#v", provider)
	}
}

func TestNewAliDNS_RequiresBothCredentials(t *testing.T) {
	tests := []struct {
		config map[string]string
		want   string
	}{
		{config: map[string]string{}, want: "failed to get AliDNS AccessKeyID"},
		{config: map[string]string{AliDNSAccessKeyID: "id"}, want: "failed to get AliDNS AccessKeySecret"},
	}
	for _, test := range tests {
		_, err := New(AliDNS, test.config)
		if err == nil || err.Error() != test.want {
			t.Fatalf("New error = %v, want %q", err, test.want)
		}
	}
}
