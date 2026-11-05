//go:build synology

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func authTestConfig(t *testing.T, handler http.HandlerFunc) (string, SynologyConfig) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := validSynologyConfig(t.TempDir())
	cfg.Synology = testDeployCfg(srv.URL)
	cfg.Synology.CertificateDesc = "DNSACME"
	cfg.Synology.Create = true
	path := filepath.Join(filepath.Dir(cfg.Runtime.StorageDir), "config.yaml")
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func stubAuthNotifications(t *testing.T) *int {
	t.Helper()
	old := notifySynologyAuthentication
	count := new(int)
	notifySynologyAuthentication = func(context.Context, string) error { *count++; return nil }
	t.Cleanup(func() { notifySynologyAuthentication = old })
	return count
}

func enrollTestDevice(t *testing.T, path, otp string) error {
	t.Helper()
	snapshot, err := loadSynologyConfigSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]string{"editToken": snapshot.EditToken, "otp": otp, "deviceName": "DNSACME test"})
	_, err = cgiSynologyAuthenticate(context.Background(), http.MethodPost, path, strings.NewReader(string(req)))
	return err
}

func TestSynologyTrustedDeviceEnrollmentReuseAndRedaction(t *testing.T) {
	for _, property := range []string{"did", "device_id"} {
		t.Run(property, func(t *testing.T) {
			stubAuthNotifications(t)
			calls := 0
			path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.RawQuery != "" {
					t.Error("credentials must stay in POST bodies")
				}
				_ = r.ParseForm()
				if r.FormValue("method") == "logout" {
					fmt.Fprint(w, `{"success":true}`)
					return
				}
				calls++
				if r.FormValue("enable_syno_token") != "yes" {
					t.Error("missing SynoToken request")
				}
				if calls == 1 {
					if r.FormValue("otp_code") != "123456" || r.FormValue("enable_device_token") != "yes" || r.FormValue("device_name") != "DNSACME test" {
						t.Error("incorrect OTP registration")
					}
					if r.FormValue("device_id") != "" {
						t.Error("enrollment reused an old device")
					}
				} else {
					if r.FormValue("otp_code") != "" || r.FormValue("device_id") != "trusted-secret" {
						t.Error("renewal did not use the trusted device without OTP")
					}
				}
				fmt.Fprintf(w, `{"success":true,"data":{"sid":"session-secret","synotoken":"csrf-secret","%s":"trusted-secret"}}`, property)
			})
			before, _ := loadSynologyConfigSnapshot(path)
			if err := enrollTestDevice(t, path, "123456"); err != nil {
				t.Fatal(err)
			}
			if err := verifySynologyConfiguredLogin(context.Background(), path, cfg); err != nil {
				t.Fatal(err)
			}
			after, _ := loadSynologyConfigSnapshot(path)
			if before.EditToken != after.EditToken || before.Config.ConfigHash() != after.Config.ConfigHash() {
				t.Fatal("auth changed certificate config or editor identity")
			}
			state, err := loadSynologyAuth(path, cfg)
			if err != nil || state.DeviceID != "trusted-secret" || state.Status != "ready" {
				t.Fatalf("unexpected state: status=%s err=%v", state.Status, err)
			}
			raw, _ := os.ReadFile(synologyAuthPath(path))
			public, _ := json.Marshal(synologyAuthView(path, cfg))
			config, _ := os.ReadFile(path)
			for _, secret := range []string{"123456", "session-secret", "csrf-secret"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("transient secret persisted: %s", secret)
				}
			}
			for _, secret := range []string{"trusted-secret", state.Identity, "123456", "session-secret", "csrf-secret"} {
				if strings.Contains(string(public), secret) || strings.Contains(string(config), secret) {
					t.Fatal("authentication secret crossed the public/config boundary")
				}
			}
			info, _ := os.Stat(synologyAuthPath(path))
			if info.Mode().Perm() != 0600 {
				t.Fatalf("mode = %o", info.Mode().Perm())
			}
			if calls != 2 {
				t.Fatalf("expected two logins, got %d", calls)
			}
		})
	}
}

func TestSynologyRevokedDeviceStopsRetriesAndCanReauthenticate(t *testing.T) {
	notifications := stubAuthNotifications(t)
	calls := 0
	revoke := false
	path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("method") == "logout" {
			fmt.Fprint(w, `{"success":true}`)
			return
		}
		calls++
		if revoke && r.FormValue("otp_code") == "" {
			fmt.Fprint(w, `{"success":false,"error":{"code":403,"text":"must-not-echo-password"}}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"data":{"sid":"sid","synotoken":"csrf","did":"device"}}`)
	})
	if err := enrollTestDevice(t, path, "123456"); err != nil {
		t.Fatal(err)
	}
	revoke = true
	for i := 0; i < 5; i++ {
		err := verifySynologyConfiguredLogin(context.Background(), path, cfg)
		if err == nil || strings.Contains(err.Error(), "must-not-echo-password") {
			t.Fatalf("unsafe/missing error: %v", err)
		}
	}
	if calls != 2 || *notifications != 1 {
		t.Fatalf("login attempts=%d notifications=%d", calls, *notifications)
	}
	if err := enrollTestDevice(t, path, "654321"); err != nil {
		t.Fatal(err)
	}
	state, _ := loadSynologyAuth(path, cfg)
	if state.Status != "ready" {
		t.Fatal("explicit OTP did not clear the blocked state")
	}
}

func TestSynologyAuthValidationAndBinding(t *testing.T) {
	stubAuthNotifications(t)
	calls := 0
	path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"success":true,"data":{"sid":"sid","synotoken":"csrf","did":"device"}}`)
	})
	for _, otp := range []string{"12345", "1234567", "12a456", "１２３４５６"} {
		if err := enrollTestDevice(t, path, otp); err == nil {
			t.Fatal("invalid OTP accepted")
		}
	}
	_, err := cgiSynologyAuthenticate(context.Background(), http.MethodPost, path, strings.NewReader(`{"editToken":"old","otp":"123456"}`))
	if !errors.Is(err, errSynologyConfigChanged) {
		t.Fatalf("stale edit: %v", err)
	}
	if _, err := cgiSynologyAuthenticate(context.Background(), http.MethodGet, path, strings.NewReader(`{}`)); err == nil {
		t.Fatal("GET authentication allowed")
	}
	if calls != 0 {
		t.Fatal("invalid request reached DSM")
	}
	if err := enrollTestDevice(t, path, "123456"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SynologyConfig){
		func(c *SynologyConfig) { c.Synology.Account = "other" },
		func(c *SynologyConfig) { c.Synology.Password = "other" },
		func(c *SynologyConfig) { c.Synology.Host = "other" },
		func(c *SynologyConfig) { c.Synology.Port++ },
		func(c *SynologyConfig) { c.Synology.Scheme = "https" },
	} {
		next := cfg
		change(&next)
		state, err := loadSynologyAuth(path, next)
		if err != nil || state.DeviceID != "" {
			t.Fatal("trusted device leaked across an account/endpoint change")
		}
	}
}

func TestSynologyAuthPreservesConcurrentConfigAndRejectsMissingDevice(t *testing.T) {
	stubAuthNotifications(t)
	var path string
	var cfg SynologyConfig
	path, cfg = authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("method") == "login" {
			edited := cfg
			edited.Synology.Account = "other"
			if err := saveSynologyConfig(path, edited); err != nil {
				t.Error(err)
			}
		}
		fmt.Fprint(w, `{"success":true,"data":{"sid":"sid","synotoken":"csrf","did":"old-device"}}`)
	})
	if err := enrollTestDevice(t, path, "123456"); !errors.Is(err, errSynologyConfigChanged) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := os.Stat(synologyAuthPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("saved credential for a replaced account")
	}
	path, _ = authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"data":{"sid":"sid","synotoken":"csrf"}}`)
	})
	if err := enrollTestDevice(t, path, "123456"); err == nil || !strings.Contains(err.Error(), "did not return") {
		t.Fatalf("missing device accepted: %v", err)
	}
}

func TestSynologyDeploymentFailureIsDurableAndRetryable(t *testing.T) {
	notifications := stubAuthNotifications(t)
	path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"data":{"sid":"sid","synotoken":"csrf"}}`)
	})
	fail := func(*synologyAPIClient) error { return errors.New("import failed") }
	if err := runSynologyDSMOperation(context.Background(), path, cfg, "", "", false, fail); err == nil {
		t.Fatal("import error swallowed")
	}
	state, _ := loadSynologyAuth(path, cfg)
	if !state.Pending || state.DeploymentError == "" || *notifications != 1 {
		t.Fatal("failed import was not surfaced")
	}
	if err := runSynologyDSMOperation(context.Background(), path, cfg, "", "", false, fail); err == nil {
		t.Fatal("import error swallowed")
	}
	if *notifications != 1 {
		t.Fatal("notification repeated for the same pending deployment")
	}
	if err := runSynologyDSMOperation(context.Background(), path, cfg, "", "", false, func(*synologyAPIClient) error { return nil }); err != nil {
		t.Fatal(err)
	}
	state, _ = loadSynologyAuth(path, cfg)
	if state.Pending || state.DeploymentError != "" || state.DeployedAt.IsZero() {
		t.Fatal("successful retry did not clear failure")
	}
}

func TestSynologyFailedLoginStillQueuesRenewedCertificate(t *testing.T) {
	stubAuthNotifications(t)
	path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"success":false,"error":{"code":403}}`) })
	called := false
	err := runSynologyDSMOperation(context.Background(), path, cfg, "", "", false, func(*synologyAPIClient) error { called = true; return nil })
	state, _ := loadSynologyAuth(path, cfg)
	if err == nil || called || !state.Pending || state.Status != "reauth_required" {
		t.Fatal("renewed certificate was not queued after a rejected login")
	}
}

func TestSynologyAuthHealthCheckIsProactiveAndBounded(t *testing.T) {
	notifications := stubAuthNotifications(t)
	calls := 0
	path, cfg := authTestConfig(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"success":false,"error":{"code":403}}`)
	})
	state := synologyAuthState{Identity: synologyAuthIdentity(cfg.Synology), DeviceID: "device", DeviceName: "DNSACME", Status: "ready", CheckedAt: time.Now().Add(-25 * time.Hour)}
	if err := saveSynologyAuth(path, cfg, state); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		maintainSynologyAuthentication(context.Background(), path, cfg)
	}
	if calls != 1 || *notifications != 1 {
		t.Fatalf("checks=%d notifications=%d", calls, *notifications)
	}
}

func TestSynologyAuthDoesNotFollowRedirects(t *testing.T) {
	calls := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `{"success":true}`) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	if err := verifySynologyLogin(context.Background(), testDeployCfg(server.URL)); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 0 {
		t.Fatal("credential-bearing request was redirected")
	}
}
