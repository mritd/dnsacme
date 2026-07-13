package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookForEvent(t *testing.T) {
	conf := &Config{
		ObtainingHook: "/tmp/obtaining",
		ObtainedHook:  "/tmp/obtained",
		FailedHook:    "/tmp/failed",
	}

	tests := map[string]string{
		"cert_obtaining": "/tmp/obtaining",
		"cert_obtained":  "/tmp/obtained",
		"cert_failed":    "/tmp/failed",
		"ignored":        "",
	}
	for event, want := range tests {
		if got := hookForEvent(conf, event); got != want {
			t.Fatalf("hookForEvent(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestCertStorageName(t *testing.T) {
	if got := certStorageName("*.example.com"); got != "wildcard_.example.com" {
		t.Fatalf("certStorageName wildcard = %q", got)
	}
	if got := certStorageName("example.com"); got != "example.com" {
		t.Fatalf("certStorageName plain = %q", got)
	}
}

func TestHookEnv(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certificates", "acme", "wildcard_.example.com")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	keyPath := filepath.Join(certDir, "wildcard_.example.com.key")
	certPath := filepath.Join(certDir, "wildcard_.example.com.crt")
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	env, err := hookEnv(context.Background(), &Config{StorageDir: dir}, map[string]any{"identifier": "*.example.com"})
	if err != nil {
		t.Fatalf("hookEnv returned error: %v", err)
	}

	assertEnvContains(t, env, "ACME_IDENTIFIER=*.example.com")
	assertEnvContains(t, env, "ACME_KEY_PATH="+keyPath)
	assertEnvContains(t, env, "ACME_CERT_PATH="+certPath)

	env, err = hookEnv(context.Background(), &Config{StorageDir: dir}, nil)
	if err != nil {
		t.Fatalf("hookEnv without identifier returned error: %v", err)
	}
	for _, item := range env {
		if strings.HasPrefix(item, "ACME_IDENTIFIER=") {
			t.Fatalf("unexpected ACME_IDENTIFIER in env: %v", env)
		}
	}
}

// A stale sibling identifier left in storage (e.g. a prior "sub.example.com" or
// "*.example.com" apply before the domain was changed to the apex) must never be
// resolved for "example.com": its file name ends with "example.com.crt" and sorts
// later, so a suffix match would import the wrong host's certificate into DSM.
func TestHookEnvIgnoresSiblingIdentifierWithSharedSuffix(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) (string, string) {
		certDir := filepath.Join(dir, "certificates", "acme", name)
		if err := os.MkdirAll(certDir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		keyPath := filepath.Join(certDir, name+".key")
		certPath := filepath.Join(certDir, name+".crt")
		if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
			t.Fatalf("write key %s: %v", name, err)
		}
		if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
			t.Fatalf("write cert %s: %v", name, err)
		}
		return keyPath, certPath
	}
	apexKey, apexCert := write("example.com")
	// Siblings whose names end with the target name; both sort after "example.com".
	write("sub.example.com")
	write("wildcard_.example.com")

	env, err := hookEnv(context.Background(), &Config{StorageDir: dir}, map[string]any{"identifier": "example.com"})
	if err != nil {
		t.Fatalf("hookEnv returned error: %v", err)
	}
	assertEnvContains(t, env, "ACME_KEY_PATH="+apexKey)
	assertEnvContains(t, env, "ACME_CERT_PATH="+apexCert)
	for _, item := range env {
		if strings.HasPrefix(item, "ACME_KEY_PATH=") && item != "ACME_KEY_PATH="+apexKey {
			t.Fatalf("resolved a sibling key instead of the apex: %q", item)
		}
		if strings.HasPrefix(item, "ACME_CERT_PATH=") && item != "ACME_CERT_PATH="+apexCert {
			t.Fatalf("resolved a sibling cert instead of the apex: %q", item)
		}
	}
}

func TestHookEnvListError(t *testing.T) {
	_, err := hookEnv(context.Background(), &Config{StorageDir: filepath.Join(t.TempDir(), "missing")}, map[string]any{"identifier": "example.com"})
	if err == nil || !strings.Contains(err.Error(), "failed to list domain") {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestOnEventRunsHook(t *testing.T) {
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certificates", "acme", "example.com")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("mkdir cert dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "example.com.key"), []byte("key"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "example.com.crt"), []byte("cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	output := filepath.Join(dir, "hook.env")
	script := filepath.Join(dir, "hook.sh")
	content := "#!/bin/sh\nprintf '%s\\n' \"$ACME_IDENTIFIER\" \"$ACME_KEY_PATH\" \"$ACME_CERT_PATH\" > " + output + "\n"
	if err := os.WriteFile(script, []byte(content), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}

	err := OnEvent(&Config{StorageDir: dir, ObtainedHook: script})(context.Background(), "cert_obtained", map[string]any{"identifier": "example.com"})
	if err != nil {
		t.Fatalf("OnEvent returned error: %v", err)
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read hook output: %v", err)
	}
	text := string(got)
	if !strings.Contains(text, "example.com\n") || !strings.Contains(text, "example.com.key") || !strings.Contains(text, "example.com.crt") {
		t.Fatalf("hook output missing expected values:\n%s", text)
	}

	if err := OnEvent(&Config{})(context.Background(), "unknown", nil); err != nil {
		t.Fatalf("unknown event should be ignored: %v", err)
	}
}

func TestOnEventRunsCustomEventHook(t *testing.T) {
	calls := 0
	err := OnEvent(&Config{
		EventHook: func(ctx context.Context, event string, data map[string]any) error {
			calls++
			if event != "cert_obtained" {
				t.Fatalf("unexpected event: %s", event)
			}
			if data["identifier"] != "example.com" {
				t.Fatalf("unexpected data: %+v", data)
			}
			return nil
		},
	})(context.Background(), "cert_obtained", map[string]any{"identifier": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected custom hook call, got %d", calls)
	}
}

func assertEnvContains(t *testing.T, env []string, want string) {
	t.Helper()
	for _, item := range env {
		if item == want {
			return
		}
	}
	t.Fatalf("env missing %q in %#v", want, env)
}
