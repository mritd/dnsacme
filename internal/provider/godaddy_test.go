//go:build godaddy || !slim

package provider

import (
	"testing"

	"github.com/libdns/godaddy"
)

func TestNewGoDaddy_MapsToken(t *testing.T) {
	got, err := New(GoDaddy, map[string]string{GoDaddyAPIToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*godaddy.Provider)
	if !ok || provider.APIToken != "token" {
		t.Fatalf("unexpected provider: %#v", got)
	}
	_, err = New(GoDaddy, map[string]string{})
	if err == nil || err.Error() != "failed to get Godaddy API Token" {
		t.Fatalf("unexpected missing-token error: %v", err)
	}
}
