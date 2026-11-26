package main

import (
	"context"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"github.com/mritd/dnsacme/internal/provider"
)

// namedDNSProvider lets route tests identify which account a solver received.
type namedDNSProvider struct {
	fakeDNSProvider
	name string
}

func TestDNSRouteKeySharesWildcardAndApex(t *testing.T) {
	for identifier, want := range map[string]string{
		"*.Example.com":  "example.com",
		"example.com.":   "example.com",
		" a.example.com": "a.example.com",
	} {
		if got := dnsRouteKey(identifier); got != want {
			t.Fatalf("dnsRouteKey(%q) = %q, want %q", identifier, got, want)
		}
	}
}

func TestRoutedDNS01SolverSelectsAccountPerIdentifier(t *testing.T) {
	oldNewDNSProvider := newDNSProvider
	defer func() { newDNSProvider = oldNewDNSProvider }()
	newDNSProvider = func(name string, config map[string]string) (certmagic.DNSProvider, error) {
		return namedDNSProvider{name: config["TOKEN"]}, nil
	}

	routes, err := dnsRouteSolversForConfig(&Config{DNSRoutes: map[string]DNSRoute{
		"*.example.com": {Provider: "fake", Config: map[string]string{"TOKEN": "wildcard"}},
		"example.com":   {Provider: "fake", Config: map[string]string{"TOKEN": "apex"}},
		"example.org":   {Provider: provider.AcmeDNS, Config: map[string]string{"TOKEN": "org", provider.AcmeDNSFullDomain: "abc.auth.acme-dns.io."}, Resolvers: []string{"9.9.9.9"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fallback := newDNS01Solver("fake", nil, nil, namedDNSProvider{name: "fallback"})
	solver := &routedDNS01Solver{fallback: fallback, routes: routes}

	accountFor := func(identifier string) string {
		selected := solver.solverFor(acme.Challenge{Identifier: acme.Identifier{Type: "dns", Value: identifier}})
		return selected.(*certmagic.DNS01Solver).DNSProvider.(namedDNSProvider).name
	}
	if got := accountFor("example.com"); got != "apex" {
		t.Fatalf("exact identifier should win over the wildcard route, got %q", got)
	}
	if got := accountFor("example.org"); got != "org" {
		t.Fatalf("example.org routed to %q", got)
	}
	if got := accountFor("unrouted.net"); got != "fallback" {
		t.Fatalf("unrouted identifier should use the fallback, got %q", got)
	}

	org := routes["example.org"]
	if org.OverrideDomain != "abc.auth.acme-dns.io" || len(org.Resolvers) != 1 || org.Resolvers[0] != "9.9.9.9" {
		t.Fatalf("ACME-DNS route lost its delegation settings: override=%q resolvers=%v", org.OverrideDomain, org.Resolvers)
	}
	if routes["example.com"].OverrideDomain != "" || routes["example.com"].Resolvers != nil {
		t.Fatal("non-ACME-DNS routes must use the system resolver and real challenge name")
	}
}

func TestStartACMEManagementInstallsRoutedSolver(t *testing.T) {
	oldNewDNSProvider := newDNSProvider
	oldManage := manageCertificates
	defer func() {
		newDNSProvider = oldNewDNSProvider
		manageCertificates = oldManage
	}()
	newDNSProvider = func(name string, config map[string]string) (certmagic.DNSProvider, error) {
		return fakeDNSProvider{}, nil
	}
	var installed any
	manageCertificates = func(ctx context.Context, cfg *certmagic.Config, domains []string) error {
		installed = cfg.Issuers[0].(*certmagic.ACMEIssuer).DNS01Solver
		return nil
	}

	conf := &Config{
		Domains:     []string{"example.com", "example.org"},
		Email:       "ops@example.com",
		StorageDir:  t.TempDir(),
		DNSProvider: "fake",
		DNSConfig:   map[string]string{"TOKEN": "a"},
		DNSRoutes:   map[string]DNSRoute{"example.org": {Provider: "fake", Config: map[string]string{"TOKEN": "b"}}},
	}
	if err := ObtainOnce(context.Background(), conf, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := installed.(*routedDNS01Solver); !ok {
		t.Fatalf("expected routed solver, got %T", installed)
	}

	conf.DNSRoutes = nil
	if err := ObtainOnce(context.Background(), conf, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := installed.(*certmagic.DNS01Solver); !ok {
		t.Fatalf("expected plain solver without routes, got %T", installed)
	}
}
