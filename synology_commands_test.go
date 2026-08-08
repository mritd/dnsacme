//go:build synology

package main

import (
	"os"
	"strings"
	"testing"
)

func TestSynologyConfigResponse_Shape(t *testing.T) {
	defaults := defaultSynologyConfig()
	if defaults.Synology.CertificateDesc != "DNSACME" {
		t.Fatalf("unexpected default certificate description: %q", defaults.Synology.CertificateDesc)
	}

	dir := t.TempDir()
	t.Setenv("DNSACME_NGINX_CONF", dir+"/nginx.conf")
	_ = os.WriteFile(dir+"/nginx.conf", []byte("server { root /usr/syno/synoman; listen 5001 default_server ssl; }"), 0o600)
	cfgPath := dir + "/config.yaml"

	resp := synologyConfigResponse(synologyConfigSnapshot{Config: defaultSynologyConfig()})
	if _, ok := resp["configHash"]; ok {
		t.Error("configHash must not be in the response")
	}
	if resp["persisted"].(bool) {
		t.Error("persisted should be false before save")
	}
	det := resp["detected"].(SynologyEndpoint)
	if !det.Detected || det.Scheme != "https" || det.Port != 5001 {
		t.Errorf("detected wrong: %+v", det)
	}

	if err := saveSynologyConfig(cfgPath, defaultSynologyConfig()); err != nil {
		t.Fatal(err)
	}
	resp = synologyConfigResponse(synologyConfigSnapshot{Config: defaultSynologyConfig(), Persisted: true})
	if !resp["persisted"].(bool) {
		t.Error("persisted should be true after save")
	}
	cfg := resp["config"].(SynologyConfig)
	if cfg.LastTest.ConfigHash != "" {
		t.Error("config.lastTest.configHash must be stripped")
	}
	if cfg.LastApply.ConfigHash != "" {
		t.Error("config.lastApply.configHash must be stripped")
	}
}

func TestCgiStatus_NoConfigHash(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"
	cfg := defaultSynologyConfig()
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	m, err := cgiStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.(map[string]any)["configHash"]; ok {
		t.Error("cgiStatus must not expose configHash")
	}
	if _, ok := m.(map[string]any)["canRenew"]; !ok {
		t.Error("cgiStatus should expose canRenew")
	}
	if got := m.(map[string]any)["editToken"]; got == "" {
		t.Errorf("cgiStatus editToken = %v, want non-empty", got)
	}
}

func TestNormalizeSynologyLogTimestamps(t *testing.T) {
	got := normalizeSynologyLogTimestamps("1.7835883915338058e+09\tinfo\tobtain\tlock acquired\n2026-07-09T17:13:11+08:00 renewal daemon failed")
	if strings.Contains(got, "1.7835883915338058e+09") {
		t.Fatalf("zap epoch timestamp was not normalized: %s", got)
	}
	if !strings.Contains(got, "\tinfo\tobtain\tlock acquired") {
		t.Fatalf("log message was not preserved: %s", got)
	}
	if !strings.Contains(got, "2026-07-09T17:13:11+08:00 renewal daemon failed") {
		t.Fatalf("existing RFC3339 log line was changed: %s", got)
	}
}
