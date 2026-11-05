package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"github.com/mritd/dnsacme/internal/provider"
)

// newDNS01Solver builds the CertMagic solver for one provider account. ACME-DNS
// publishes its TXT value on the delegated full domain and is the only provider
// that observes propagation through the configured recursive resolvers.
func newDNS01Solver(providerName string, config map[string]string, resolvers []string, dnsProvider certmagic.DNSProvider) *certmagic.DNS01Solver {
	var solverResolvers []string
	var overrideDomain string
	if strings.EqualFold(providerName, provider.AcmeDNS) {
		solverResolvers = append([]string(nil), resolvers...)
		overrideDomain = strings.TrimSuffix(strings.TrimSpace(config[provider.AcmeDNSFullDomain]), ".")
	}
	return &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider:    dnsProvider,
			Resolvers:      solverResolvers,
			OverrideDomain: overrideDomain,
		},
	}
}

// dnsRouteKey maps a certificate identifier to the name its DNS-01 challenge is
// published under. ACME authorizations carry wildcard names without "*.", so
// "*.example.com" and "example.com" intentionally share one key.
func dnsRouteKey(identifier string) string {
	identifier = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(identifier), "."))
	return strings.TrimPrefix(identifier, "*.")
}

// dnsRouteSolversForConfig constructs one solver per routed challenge name. An
// exact (non-wildcard) identifier wins over a wildcard route for the same name.
func dnsRouteSolversForConfig(conf *Config) (map[string]*certmagic.DNS01Solver, error) {
	if len(conf.DNSRoutes) == 0 {
		return nil, nil
	}
	routes := make(map[string]*certmagic.DNS01Solver, len(conf.DNSRoutes))
	exact := make(map[string]bool, len(conf.DNSRoutes))
	for identifier, route := range conf.DNSRoutes {
		key := dnsRouteKey(identifier)
		if key == "" {
			continue
		}
		isExact := !strings.HasPrefix(strings.TrimSpace(identifier), "*.")
		if _, ok := routes[key]; ok && (exact[key] || !isExact) {
			continue
		}
		dnsProvider, err := newDNSProvider(route.Provider, route.Config)
		if err != nil {
			return nil, fmt.Errorf("DNS provider for %s: %w", identifier, err)
		}
		routes[key] = newDNS01Solver(route.Provider, route.Config, route.Resolvers, dnsProvider)
		exact[key] = isExact
	}
	return routes, nil
}

// routedDNS01Solver dispatches every DNS-01 challenge to the provider account
// configured for its identifier, so one CertMagic runtime can manage names
// hosted by different DNS providers or accounts.
type routedDNS01Solver struct {
	fallback acmez.Solver
	routes   map[string]*certmagic.DNS01Solver
}

func (s *routedDNS01Solver) solverFor(challenge acme.Challenge) acmez.Solver {
	if solver, ok := s.routes[dnsRouteKey(challenge.Identifier.Value)]; ok {
		return solver
	}
	return s.fallback
}

func (s *routedDNS01Solver) Present(ctx context.Context, challenge acme.Challenge) error {
	return s.solverFor(challenge).Present(ctx, challenge)
}

// Wait forwards to the selected solver when it supports propagation checks;
// acmez only calls Wait on solvers that implement acmez.Waiter.
func (s *routedDNS01Solver) Wait(ctx context.Context, challenge acme.Challenge) error {
	if waiter, ok := s.solverFor(challenge).(acmez.Waiter); ok {
		return waiter.Wait(ctx, challenge)
	}
	return nil
}

func (s *routedDNS01Solver) CleanUp(ctx context.Context, challenge acme.Challenge) error {
	return s.solverFor(challenge).CleanUp(ctx, challenge)
}
