package provider

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeAcmeDNSServerURL validates the ACME-DNS API base URL used by both
// the provider update client and Synology's explicit registration endpoint.
func NormalizeAcmeDNSServerURL(raw string) (string, error) {
	serverURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || serverURL.Scheme == "" || serverURL.Hostname() == "" {
		return "", fmt.Errorf("invalid ACME-DNS server URL")
	}
	if serverURL.Scheme != "http" && serverURL.Scheme != "https" {
		return "", fmt.Errorf("invalid ACME-DNS server URL scheme")
	}
	if serverURL.User != nil || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return "", fmt.Errorf("invalid ACME-DNS server URL")
	}
	serverURL.Path = strings.TrimRight(serverURL.Path, "/")
	serverURL.RawPath = ""
	return serverURL.String(), nil
}
