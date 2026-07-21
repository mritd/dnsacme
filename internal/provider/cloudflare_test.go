//go:build cloudflare || !slim

package provider

import (
	"testing"

	"github.com/libdns/cloudflare"
)

func TestNewCloudflare_MapsToken(t *testing.T) {
	got, err := New(Cloudflare, map[string]string{CloudflareAPIToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*cloudflare.Provider)
	if !ok || provider.APIToken != "token" {
		t.Fatalf("unexpected provider: %#v", got)
	}
	_, err = New(Cloudflare, map[string]string{})
	if err == nil || err.Error() != "failed to get Cloudflare API Token" {
		t.Fatalf("unexpected missing-token error: %v", err)
	}
}
