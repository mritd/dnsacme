package main

import "github.com/caddyserver/certmagic"

type Config struct {
	Domains       []string
	Email         string
	ZeroSSLCA     bool
	StorageDir    string
	KeyType       string
	DNSProvider   string
	DNSConfig     map[string]string
	ObtainingHook string
	ObtainedHook  string
	FailedHook    string

	keyType certmagic.KeyType
}

type Providers []string

func (p Providers) Len() int           { return len(p) }
func (p Providers) Less(i, j int) bool { return p[i] < p[j] }
func (p Providers) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
