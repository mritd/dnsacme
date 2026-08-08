//go:build synology

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mritd/dnsacme/internal/provider"
)

func TestCGIAcmeDNSRegister_ReturnsAccountWithoutPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"example.com"}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/register" {
			t.Fatalf("unexpected registration request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
			t.Fatalf("content type = %q", got)
		}
		_, _ = w.Write([]byte(`{"username":"user","password":"secret","subdomain":"abc-123","fulldomain":"abc-123.auth.example."}`))
	}))
	defer server.Close()

	payload, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, path, bytes.NewBufferString(`{"serverURL":"`+server.URL+`/api///"}`))
	if err != nil {
		t.Fatal(err)
	}
	response := payload.(map[string]string)
	if response["password"] != "secret" || response["serverURL"] != server.URL+"/api" {
		t.Fatalf("unexpected registration: %#v", response)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DNS.Provider == provider.AcmeDNS {
		t.Fatalf("registration unexpectedly wrote config: %#v", loaded.DNS)
	}
}

func TestCGIAcmeDNSRegister_DoesNotRequireConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"user","password":"secret","subdomain":"abc","fulldomain":"abc.auth.example"}`))
	}))
	defer server.Close()
	payload, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, path, bytes.NewBufferString(`{"serverURL":"`+server.URL+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if payload.(map[string]string)["password"] != "secret" {
		t.Fatalf("unexpected registration: %#v", payload)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("registration unexpectedly touched config: %v", err)
	}
}

func TestCGIAcmeDNSRegister_DoesNotWaitForRequestEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"user","password":"secret","subdomain":"abc","fulldomain":"abc.auth.example"}`))
	}))
	defer server.Close()

	client, cgi := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer func() { _ = cgi.Close() }()
		done <- serveSynologyCGI(
			context.Background(),
			filepath.Join(t.TempDir(), "config.yaml"),
			queryEnv("action=acmedns-register", http.MethodPost),
			cgi,
			cgi,
		)
	}()

	if err := client.SetDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	request := `{"serverURL":"` + server.URL + `"}`
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatal(err)
	}
	response, readErr := io.ReadAll(client)
	_ = client.Close()
	serveErr := <-done
	if readErr != nil {
		t.Fatalf("CGI waited for request EOF instead of replying after one JSON value: %v", readErr)
	}
	if serveErr != nil {
		t.Fatal(serveErr)
	}
	parsed := parseCGIResponse(t, string(response))
	if !parsed.Success {
		t.Fatalf("registration failed: %s", parsed.Error)
	}
}

func TestCGIAcmeDNSRegister_IgnoresConcurrentConfigChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"example.com"}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte(`{"username":"user","password":"secret","subdomain":"abc","fulldomain":"abc.auth.example"}`))
	}))
	defer server.Close()
	result := make(chan struct {
		payload any
		err     error
	}, 1)
	go func() {
		payload, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, path, strings.NewReader(`{"serverURL":"`+server.URL+`"}`))
		result <- struct {
			payload any
			err     error
		}{payload, err}
	}()
	<-started
	if _, err := mutateSynologyConfig(path, func(current *SynologyConfig, _ string) (bool, error) {
		current.ACME.Email = "changed@example.com"
		current.ACME.Domains = nil
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	got := <-result
	if got.err != nil {
		t.Fatal(got.err)
	}
	response := got.payload.(map[string]string)
	if response["password"] != "secret" {
		t.Fatalf("registration response = %#v", response)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ACME.Email != "changed@example.com" || len(loaded.ACME.Domains) != 0 || loaded.DNS.Provider == provider.AcmeDNS {
		t.Fatalf("registration overwrote concurrent change: %#v", loaded)
	}
}

func TestCGIConfig_ValidatesAndNormalizesManualAcmeDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	current := defaultSynologyConfig()
	if err := saveSynologyConfig(path, current); err != nil {
		t.Fatal(err)
	}
	next := current
	next.DNS = SynologyDNSConfig{Provider: provider.AcmeDNS, Config: map[string]string{
		provider.AcmeDNSUsername: " user ", provider.AcmeDNSPassword: " password ", provider.AcmeDNSSubdomain: "account", provider.AcmeDNSFullDomain: "account.auth.example.", provider.AcmeDNSServerURL: " https://auth.example/api/// ",
	}}
	data, _ := json.Marshal(next)
	if _, err := cgiConfig(http.MethodPost, path, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DNS.Config[provider.AcmeDNSFullDomain] != "account.auth.example" || loaded.DNS.Config[provider.AcmeDNSServerURL] != "https://auth.example/api" {
		t.Fatalf("manual account was not normalized: %#v", loaded.DNS.Config)
	}
	next.DNS.Config[provider.AcmeDNSFullDomain] = "bad..name"
	data, _ = json.Marshal(next)
	if _, err := cgiConfig(http.MethodPost, path, bytes.NewReader(data)); err == nil {
		t.Fatal("invalid manual full domain unexpectedly persisted")
	}
}

func TestCGIAcmeDNSRegister_RejectsRemoteFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		code int
	}{
		{name: "non 2xx", code: http.StatusForbidden, body: "no"},
		{name: "malformed", code: http.StatusOK, body: "{"},
		{name: "incomplete", code: http.StatusOK, body: `{"username":"u"}`},
		{name: "invalid name", code: http.StatusOK, body: `{"username":"u","password":"p","subdomain":"two.labels","fulldomain":"a.example"}`},
		{name: "oversized", code: http.StatusOK, body: `{"username":"` + strings.Repeat("a", maxAcmeDNSRegistrationResponseBytes) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			cfg := defaultSynologyConfig()
			cfg.ACME.Domains = []string{"example.com"}
			if err := saveSynologyConfig(path, cfg); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.code)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, path, strings.NewReader(`{"serverURL":"`+server.URL+`"}`))
			if err == nil {
				t.Fatal("registration unexpectedly succeeded")
			}
			loaded, loadErr := loadSynologyConfig(path)
			if loadErr != nil || loaded.DNS.Provider == provider.AcmeDNS {
				t.Fatalf("remote failure modified config: %#v, %v", loaded.DNS, loadErr)
			}
		})
	}
}

func TestCGIAcmeDNSRegister_DoesNotFollowRedirect(t *testing.T) {
	var initialRequests, redirectRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			initialRequests++
			http.Redirect(w, r, "/redirected", http.StatusFound)
		case "/redirected":
			redirectRequests++
			_, _ = w.Write([]byte(`{"username":"user","password":"secret","subdomain":"abc","fulldomain":"abc.auth.example"}`))
		default:
			t.Fatalf("unexpected request path %q", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, "", strings.NewReader(`{"serverURL":"`+server.URL+`"}`))
	if err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("redirect registration error = %v, want 302", err)
	}
	if initialRequests != 1 || redirectRequests != 0 {
		t.Fatalf("requests = initial %d redirected %d, want 1 and 0", initialRequests, redirectRequests)
	}
}

func TestCGIAcmeDNSRegister_MethodAndTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := cgiAcmeDNSRegister(context.Background(), http.MethodGet, path, strings.NewReader(`{}`)); err == nil {
		t.Fatal("GET unexpectedly succeeded")
	}
	var output bytes.Buffer
	if err := serveSynologyCGI(context.Background(), path, queryEnv("action=acmedns-register", http.MethodGet), strings.NewReader(`{}`), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "Status: 405 ") {
		t.Fatalf("GET CGI status = %q", output.String())
	}
	originalClient := newAcmeDNSRegistrationHTTPClient
	newAcmeDNSRegistrationHTTPClient = func() *http.Client { return &http.Client{Timeout: time.Millisecond} }
	t.Cleanup(func() { newAcmeDNSRegistrationHTTPClient = originalClient })
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"example.com"}
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(20 * time.Millisecond) }))
	defer server.Close()
	if _, err := cgiAcmeDNSRegister(context.Background(), http.MethodPost, path, strings.NewReader(`{"serverURL":"`+server.URL+`"}`)); err == nil {
		t.Fatal("timeout unexpectedly succeeded")
	}
}

func TestAcmeDNSRegistrationValidation(t *testing.T) {
	for _, value := range []string{"bad\nname", strings.Repeat("x", 1025)} {
		account := acmeDNSRegistrationAccount{Username: value, Password: "p", Subdomain: "a", FullDomain: "a.example"}
		if err := validateAcmeDNSRegistrationAccount(&account); err == nil {
			t.Fatalf("invalid credential %q was accepted", value)
		}
	}
	data, _ := json.Marshal(acmeDNSRegistrationRequest{ServerURL: "https://auth.example"})
	if !bytes.Contains(data, []byte("serverURL")) {
		t.Fatal("registration request no longer contains server URL")
	}
}
