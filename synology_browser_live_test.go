//go:build synology

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Opt-in, on-device only: a trusted operational login supplies a transient test
// browser cookie. No SID, token, password or remote response is printed.
func TestNativeBrowserAuthorizationLive(t *testing.T) {
	path := os.Getenv("DNSACME_LIVE_BROWSER_CONFIG")
	if path == "" {
		t.Skip("on-device opt-in test")
	}
	cfg, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal("config unavailable")
	}
	state, err := loadSynologyAuth(path, cfg)
	if err != nil {
		t.Fatal("trust unavailable")
	}
	cfg.Synology.DeviceID, cfg.Synology.DeviceName = state.DeviceID, state.DeviceName
	c := newSynologyAPIClient(cfg.Synology)
	if err := c.login(context.Background()); err != nil {
		t.Fatal("trusted login failed")
	}
	defer c.logout(context.Background())
	err = func() error {
		values := map[string]string{
			"HTTP_COOKIE": "id=" + c.sid, "REMOTE_ADDR": "127.0.0.1", "SERVER_ADDR": "127.0.0.1", "SERVER_PORT": fmt.Sprint(cfg.Synology.Port), "REQUEST_METHOD": "GET", "QUERY_STRING": "action=csrf", "HTTP_HOST": "127.0.0.1", "HTTPS": "on", "HTTP_X_SYNO_TOKEN": c.token,
		}
		get := func(k string) string { return values[k] }
		var out bytes.Buffer
		if e := serveSynologyCGI(context.Background(), path, get, strings.NewReader(""), &out); e != nil {
			return e
		}
		if !strings.HasPrefix(out.String(), "Status: 200") {
			return fmt.Errorf("native session bootstrap rejected")
		}
		_, body, _ := strings.Cut(out.String(), "\r\n\r\n")
		var response struct {
			Data struct {
				Token string `json:"csrfToken"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &response) != nil || response.Data.Token == "" {
			return fmt.Errorf("bootstrap missing token")
		}
		values["HTTP_X_DNSACME_CSRF"], values["QUERY_STRING"] = response.Data.Token, "action=config"
		out.Reset()
		_ = serveSynologyCGI(context.Background(), path, get, strings.NewReader(""), &out)
		if !strings.HasPrefix(out.String(), "Status: 200") {
			return fmt.Errorf("authenticated config rejected")
		}
		values["HTTP_X_DNSACME_CSRF"] = "wrong"
		out.Reset()
		_ = serveSynologyCGI(context.Background(), path, get, strings.NewReader(""), &out)
		if !strings.HasPrefix(out.String(), "Status: 403") {
			return fmt.Errorf("invalid CSRF accepted")
		}
		values["HTTP_COOKIE"] = ""
		out.Reset()
		_ = serveSynologyCGI(context.Background(), path, get, strings.NewReader(""), &out)
		if !strings.HasPrefix(out.String(), "Status: 401") {
			return fmt.Errorf("anonymous read accepted")
		}
		return nil
	}()
	if err != nil {
		t.Fatal("on-device browser authorization check failed:", err)
	}
}
