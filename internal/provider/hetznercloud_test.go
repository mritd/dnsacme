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

func TestNewHetznerCloud_MetadataKeyConstructsProvider(t *testing.T) {
	for _, definition := range Definitions() {
		if definition.Name != HetznerCloud {
			continue
		}
		if len(definition.Fields) != 1 {
			t.Fatalf("Hetzner Cloud fields = %d, want 1", len(definition.Fields))
		}
		if _, err := New(definition.Name, map[string]string{definition.Fields[0].Key: "token"}); err != nil {
			t.Fatalf("metadata-produced config cannot construct provider: %v", err)
		}
		return
	}
	t.Fatal("Hetzner Cloud definition not found")
}
