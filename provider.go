package main

import "github.com/caddyserver/certmagic"

// providerFn contains all supported DNS providers
var providerFn = make(map[string]func(conf *Config) (certmagic.ACMEDNSProvider, error))
