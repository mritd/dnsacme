package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func testDeployCfg(serverURL string) SynologyDeployConfig {
	u, _ := url.Parse(serverURL)
	port, _ := strconv.Atoi(u.Port())
	return SynologyDeployConfig{Scheme: "http", Host: u.Hostname(), Port: port, Account: "admin", Password: "pw"}
}

func TestVerifySynologyLogin(t *testing.T) {
	tests := []struct {
		name       string
		loginBody  string
		wantErr    bool
		wantLogout bool
	}{
		{"success", `{"success":true,"data":{"sid":"abc","synotoken":"token-abc"}}`, false, true},
		{"auth failure", `{"success":false,"error":{"code":400}}`, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var methods []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "auth.cgi") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = r.ParseForm()
				method := r.FormValue("method")
				methods = append(methods, method)
				if method == "logout" {
					_, _ = w.Write([]byte(`{"success":true}`))
					return
				}
				_, _ = w.Write([]byte(tt.loginBody))
			}))
			defer srv.Close()
			err := verifySynologyLogin(context.Background(), testDeployCfg(srv.URL))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			sawLogin, sawLogout := false, false
			for _, m := range methods {
				if m == "login" {
					sawLogin = true
				}
				if m == "logout" {
					sawLogout = true
				}
			}
			if !sawLogin {
				t.Error("expected a login call")
			}
			if sawLogout != tt.wantLogout {
				t.Errorf("logout called=%v, want=%v", sawLogout, tt.wantLogout)
			}
		})
	}
}
