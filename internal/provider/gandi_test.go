//go:build gandi || !slim

package provider

import (
	"testing"

	"github.com/libdns/gandi"
)

func TestNewGandi_MapsToken(t *testing.T) {
	got, err := New(Gandi, map[string]string{GandiAPIToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*gandi.Provider)
	if !ok || provider.BearerToken != "token" {
		t.Fatalf("unexpected provider: %#v", got)
	}
	_, err = New(Gandi, map[string]string{})
	if err == nil || err.Error() != "failed to get Gandi API Token" {
		t.Fatalf("unexpected missing-token error: %v", err)
	}
}
