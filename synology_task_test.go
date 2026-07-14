//go:build synology

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSynologyTest_RequiresDSMAccount(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DNSACME_CONFIG", dir+"/config.yaml")
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"example.com"}
	cfg.ACME.Email = "a@b.com"
	cfg.DNS.Config = map[string]string{ENV_CLOUDFLARE_API_TOKEN: "t"}
	cfg.Synology.Account = ""
	cfg.Synology.Password = ""
	if err := saveSynologyConfig("", cfg); err != nil {
		t.Fatal(err)
	}
	_, err := runSynologyTest(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "account") {
		t.Fatalf("expected account-required error, got %v", err)
	}
}

func TestValidateConfigForSynologyRejectsUnsafeIdentifier(t *testing.T) {
	cfg := defaultSynologyConfig()
	cfg.ACME.Domains = []string{"../../outside"}
	cfg.ACME.Email = "a@b.com"
	cfg.DNS.Config = map[string]string{ENV_CLOUDFLARE_API_TOKEN: "t"}
	cfg.Synology.Account = "admin"
	cfg.Synology.Password = "password"
	if err := validateConfigForSynology(cfg, true); err == nil || !strings.Contains(err.Error(), "invalid public certificate identifier") {
		t.Fatalf("expected unsafe identifier error, got %v", err)
	}
}

func TestRemoveStoredCertificateRejectsPathEscape(t *testing.T) {
	storageDir := filepath.Join(t.TempDir(), "storage")
	victim := filepath.Join(storageDir, "victim")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(victim, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := removeStoredCertificate(storageDir, "../../victim"); err == nil || !strings.Contains(err.Error(), "outside storage") {
		t.Fatalf("expected path containment error, got %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("path escape removed marker: %v", err)
	}
}
