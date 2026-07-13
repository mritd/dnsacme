package main

import (
	"context"

	"github.com/caddyserver/certmagic"
)

// Config contains the provider-independent inputs used to build one CertMagic
// runtime. Synology derives this value from its persisted package config.
type Config struct {
	Domains       []string
	Email         string
	ZeroSSLCA     bool
	CA            string // Explicit ACME directory URL; bypasses ZeroSSL and its EAB branch.
	StorageDir    string
	KeyType       string
	DNSProvider   string
	DNSConfig     map[string]string
	ObtainingHook string
	ObtainedHook  string
	FailedHook    string
	// RenewalWindowRatio is the remaining:total lifetime fraction below which
	// CertMagic renews. Zero (or any out-of-range value) falls back through
	// resolveRenewalWindowRatio to the DNSACME_RENEWAL_WINDOW_RATIO environment
	// variable and finally CertMagic's default of 1/3.
	RenewalWindowRatio float64
	// EventHook receives CertMagic events after the optional command hook. Its
	// returned error is passed back to CertMagic, where pre- and post-event error
	// handling differs. Synology uses it to deploy renewed certificates into DSM.
	EventHook func(ctx context.Context, event string, data map[string]any) error

	// EAB credentials associate issuance with an existing ZeroSSL account only
	// when ZeroSSLCA selects the legacy ZeroSSL branch and CA is empty.
	EABKeyID   string // EAB Key Identifier
	EABHMACKey string // EAB HMAC Key

	keyType certmagic.KeyType
}

// Providers implements sort.Interface for provider names.
type Providers []string

func (p Providers) Len() int           { return len(p) }
func (p Providers) Less(i, j int) bool { return p[i] < p[j] }
func (p Providers) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
