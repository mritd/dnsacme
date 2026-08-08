//go:build acmedns || !slim

package provider

import (
	"fmt"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/acmedns"
)

// newAcmeDNS validates ACME-DNS credentials and constructs its libdns provider.
func newAcmeDNS(config map[string]string) (certmagic.DNSProvider, error) {
	username, err := requiredAcmeDNSValue(config, AcmeDNSUsername)
	if err != nil {
		return nil, err
	}
	password, err := requiredAcmeDNSValue(config, AcmeDNSPassword)
	if err != nil {
		return nil, err
	}
	subdomain, err := requiredAcmeDNSValue(config, AcmeDNSSubdomain)
	if err != nil {
		return nil, err
	}
	serverURL, err := NormalizeAcmeDNSServerURL(config[AcmeDNSServerURL])
	if err != nil {
		return nil, err
	}

	return &acmedns.Provider{
		Username:  username,
		Password:  password,
		Subdomain: subdomain,
		ServerURL: serverURL,
	}, nil
}

func requiredAcmeDNSValue(config map[string]string, key string) (string, error) {
	value := strings.TrimSpace(config[key])
	if value == "" {
		return "", fmt.Errorf("failed to get ACME-DNS %s", key)
	}
	return value, nil
}

// init registers ACME-DNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: AcmeDNS, Label: "ACME-DNS", Fields: []Field{
		{Key: AcmeDNSUsername, Label: "Username", Required: true},
		{Key: AcmeDNSPassword, Label: "Password", Secret: true, Required: true},
		{Key: AcmeDNSSubdomain, Label: "Subdomain", Required: true, Placeholder: "e.g. 8c72f60d"},
		{Key: AcmeDNSFullDomain, Label: "Full Domain", Required: true, Placeholder: "e.g. 8c72f60d.auth.acme-dns.io"},
		{Key: AcmeDNSServerURL, Label: "Server URL", Required: true, Placeholder: "https://auth.acme-dns.io"},
	}}, newAcmeDNS)
}
