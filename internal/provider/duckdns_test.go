//go:build duckdns || !slim

package provider

import (
	"testing"

	"github.com/libdns/duckdns"
)

func TestNewDuckDNS_MapsCredentials(t *testing.T) {
	got, err := New(DuckDNS, map[string]string{DuckDNSAPIToken: "token", DuckDNSOverrideDomain: "duck.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*duckdns.Provider)
	if !ok || provider.APIToken != "token" || provider.OverrideDomain != "duck.example.com" {
		t.Fatalf("unexpected provider: %#v", got)
	}
}
