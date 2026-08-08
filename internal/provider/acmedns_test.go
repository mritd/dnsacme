//go:build acmedns || !slim

package provider

import (
	"testing"

	"github.com/libdns/acmedns"
)

func TestNewAcmeDNS_MapsCredentialsAndNormalizesServerURL(t *testing.T) {
	got, err := New(AcmeDNS, map[string]string{
		AcmeDNSUsername:  "username",
		AcmeDNSPassword:  "password",
		AcmeDNSSubdomain: "subdomain",
		AcmeDNSServerURL: " https://auth.acme-dns.io/api/// ",
	})
	if err != nil {
		t.Fatal(err)
	}

	provider, ok := got.(*acmedns.Provider)
	if !ok {
		t.Fatalf("New(%q) returned %T, want *acmedns.Provider", AcmeDNS, got)
	}
	if provider.Username != "username" || provider.Password != "password" || provider.Subdomain != "subdomain" || provider.ServerURL != "https://auth.acme-dns.io/api" {
		t.Fatalf("unexpected provider: %#v", provider)
	}
}

func TestNewAcmeDNS_FullDomainIsOptional(t *testing.T) {
	_, err := New(AcmeDNS, map[string]string{
		AcmeDNSUsername:  "username",
		AcmeDNSPassword:  "password",
		AcmeDNSSubdomain: "subdomain",
		AcmeDNSServerURL: "https://auth.acme-dns.io",
	})
	if err != nil {
		t.Fatalf("New(%q) returned error without %s: %v", AcmeDNS, AcmeDNSFullDomain, err)
	}
}

func TestNewAcmeDNS_RejectsInvalidConfig(t *testing.T) {
	valid := map[string]string{
		AcmeDNSUsername:  "username",
		AcmeDNSPassword:  "password",
		AcmeDNSSubdomain: "subdomain",
		AcmeDNSServerURL: "https://auth.acme-dns.io",
	}

	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "missing username", mutate: func(config map[string]string) { delete(config, AcmeDNSUsername) }},
		{name: "empty password", mutate: func(config map[string]string) { config[AcmeDNSPassword] = " " }},
		{name: "missing subdomain", mutate: func(config map[string]string) { delete(config, AcmeDNSSubdomain) }},
		{name: "missing server URL", mutate: func(config map[string]string) { delete(config, AcmeDNSServerURL) }},
		{name: "URL without hostname", mutate: func(config map[string]string) { config[AcmeDNSServerURL] = "https://:443" }},
		{name: "unsupported URL scheme", mutate: func(config map[string]string) { config[AcmeDNSServerURL] = "ftp://auth.acme-dns.io" }},
		{name: "URL userinfo", mutate: func(config map[string]string) { config[AcmeDNSServerURL] = "https://user@auth.acme-dns.io" }},
		{name: "URL query", mutate: func(config map[string]string) { config[AcmeDNSServerURL] = "https://auth.acme-dns.io?query=value" }},
		{name: "URL fragment", mutate: func(config map[string]string) { config[AcmeDNSServerURL] = "https://auth.acme-dns.io#fragment" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := make(map[string]string, len(valid))
			for key, value := range valid {
				config[key] = value
			}
			test.mutate(config)
			if _, err := New(AcmeDNS, config); err == nil {
				t.Fatal("New() returned nil error")
			}
		})
	}
}

func TestAcmeDNSDefinition(t *testing.T) {
	definition, ok := findDefinition(AcmeDNS)
	if !ok {
		t.Fatalf("Definitions() did not include %q", AcmeDNS)
	}
	want := []Field{
		{Key: AcmeDNSUsername, Label: "Username", Required: true},
		{Key: AcmeDNSPassword, Label: "Password", Secret: true, Required: true},
		{Key: AcmeDNSSubdomain, Label: "Subdomain", Required: true, Placeholder: "e.g. 8c72f60d"},
		{Key: AcmeDNSFullDomain, Label: "Full Domain", Required: true, Placeholder: "e.g. 8c72f60d.auth.acme-dns.io"},
		{Key: AcmeDNSServerURL, Label: "Server URL", Required: true, Placeholder: "https://auth.acme-dns.io"},
	}
	if len(definition.Fields) != len(want) {
		t.Fatalf("ACME-DNS fields = %#v, want %#v", definition.Fields, want)
	}
	for i := range want {
		if definition.Fields[i] != want[i] {
			t.Fatalf("ACME-DNS field %d = %#v, want %#v", i, definition.Fields[i], want[i])
		}
	}
}

func findDefinition(name string) (Definition, bool) {
	for _, definition := range Definitions() {
		if definition.Name == name {
			return definition, true
		}
	}
	return Definition{}, false
}
