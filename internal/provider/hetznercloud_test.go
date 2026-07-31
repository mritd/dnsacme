//go:build hetznercloud || !slim

package provider

import (
	"testing"

	"github.com/libdns/hetzner/v2"
)

func TestNewHetznerCloud_MapsToken(t *testing.T) {
	got, err := New(HetznerCloud, map[string]string{HetznerCloudAPIToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*hetzner.Provider)
	if !ok || provider.APIToken != "token" {
		t.Fatalf("unexpected provider: %#v", got)
	}
	_, err = New(HetznerCloud, map[string]string{})
	if err == nil || err.Error() != "failed to get Hetzner Cloud API Token" {
		t.Fatalf("unexpected missing-token error: %v", err)
	}
}
