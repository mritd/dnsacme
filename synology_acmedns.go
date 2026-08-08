//go:build synology

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/mritd/dnsacme/internal/provider"
)

const maxAcmeDNSRegistrationResponseBytes = 1 << 20

var newAcmeDNSRegistrationHTTPClient = func() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type acmeDNSRegistrationRequest struct {
	ServerURL string `json:"serverURL"`
}

// acmeDNSRegistrationAccount is the one-time credential response from an
// ACME-DNS server. It is returned only by registration, never by config reads.
type acmeDNSRegistrationAccount struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

func cgiAcmeDNSRegister(ctx context.Context, method, configPath string, input io.Reader) (any, error) {
	if method != http.MethodPost {
		return nil, fmt.Errorf("method %s is not allowed", method)
	}
	var request acmeDNSRegistrationRequest
	decoder := json.NewDecoder(io.LimitReader(input, maxAcmeDNSRegistrationResponseBytes+1))
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("invalid ACME-DNS registration request: %w", err)
	}
	// DSM carries CGI stdin and stdout over one bidirectional socket and does not
	// close the request side before waiting for the response. A second Decode to
	// require EOF would therefore deadlock before registration starts.
	serverURL, err := provider.NormalizeAcmeDNSServerURL(request.ServerURL)
	if err != nil {
		return nil, err
	}

	account, err := registerAcmeDNSAccount(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	if err := validateAcmeDNSRegistrationAccount(&account); err != nil {
		return nil, err
	}

	return acmeDNSRegistrationResponse(account, serverURL), nil
}

func registerAcmeDNSAccount(ctx context.Context, serverURL string) (acmeDNSRegistrationAccount, error) {
	endpoint, err := url.Parse(serverURL)
	if err != nil {
		return acmeDNSRegistrationAccount{}, err
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/register"
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), strings.NewReader("{}"))
	if err != nil {
		return acmeDNSRegistrationAccount{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := newAcmeDNSRegistrationHTTPClient().Do(request)
	if err != nil {
		return acmeDNSRegistrationAccount{}, fmt.Errorf("ACME-DNS registration request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return acmeDNSRegistrationAccount{}, fmt.Errorf("ACME-DNS registration returned status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxAcmeDNSRegistrationResponseBytes+1))
	if err != nil {
		return acmeDNSRegistrationAccount{}, errors.New("invalid ACME-DNS registration response")
	}
	if len(body) > maxAcmeDNSRegistrationResponseBytes {
		return acmeDNSRegistrationAccount{}, errors.New("ACME-DNS registration response is too large")
	}
	var account acmeDNSRegistrationAccount
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&account); err != nil {
		return acmeDNSRegistrationAccount{}, errors.New("invalid ACME-DNS registration response")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return acmeDNSRegistrationAccount{}, errors.New("invalid ACME-DNS registration response")
	}
	return account, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func validateAcmeDNSRegistrationAccount(account *acmeDNSRegistrationAccount) error {
	username, err := validateAcmeDNSCredential("username", account.Username)
	if err != nil {
		return err
	}
	password, err := validateAcmeDNSCredential("password", account.Password)
	if err != nil {
		return err
	}
	subdomain := strings.TrimSpace(strings.TrimSuffix(account.Subdomain, "."))
	if !validDNSLabel(subdomain) {
		return errors.New("invalid ACME-DNS subdomain")
	}
	fullDomain := strings.TrimSpace(strings.TrimSuffix(account.FullDomain, "."))
	if !validDNSName(fullDomain) {
		return errors.New("invalid ACME-DNS full domain")
	}
	account.Username = username
	account.Password = password
	account.Subdomain = subdomain
	account.FullDomain = fullDomain
	return nil
}

// normalizeManualAcmeDNSConfig makes browser-submitted account fields obey the
// same contract as remote registration. This keeps crafted CGI saves from
// persisting unusable delegated-CNAME credentials.
func normalizeManualAcmeDNSConfig(dns *SynologyDNSConfig) error {
	if dns.Provider != provider.AcmeDNS {
		return nil
	}
	account := acmeDNSRegistrationAccount{
		Username:   dns.Config[provider.AcmeDNSUsername],
		Password:   dns.Config[provider.AcmeDNSPassword],
		Subdomain:  dns.Config[provider.AcmeDNSSubdomain],
		FullDomain: dns.Config[provider.AcmeDNSFullDomain],
	}
	if err := validateAcmeDNSRegistrationAccount(&account); err != nil {
		return err
	}
	serverURL, err := provider.NormalizeAcmeDNSServerURL(dns.Config[provider.AcmeDNSServerURL])
	if err != nil {
		return err
	}
	dns.Config[provider.AcmeDNSUsername] = account.Username
	dns.Config[provider.AcmeDNSPassword] = account.Password
	dns.Config[provider.AcmeDNSSubdomain] = account.Subdomain
	dns.Config[provider.AcmeDNSFullDomain] = account.FullDomain
	dns.Config[provider.AcmeDNSServerURL] = serverURL
	return nil
}

func validateAcmeDNSCredential(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 1024 {
		return "", fmt.Errorf("invalid ACME-DNS %s", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("invalid ACME-DNS %s", name)
		}
	}
	return value, nil
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return net.ParseIP(value) == nil
}

func acmeDNSRegistrationResponse(account acmeDNSRegistrationAccount, serverURL string) map[string]string {
	return map[string]string{
		"username":   account.Username,
		"password":   account.Password,
		"subdomain":  account.Subdomain,
		"fulldomain": account.FullDomain,
		"serverURL":  serverURL,
	}
}
