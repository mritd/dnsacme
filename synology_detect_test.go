//go:build synology

package main

import (
	"os"
	"testing"
)

const nginxFixtureReal = `
http {
    upstream synoscgi { server unix:/run/synoscgi_socket.sock; }
    server {
        listen 5000 default_server;
        listen [::]:5000 default_server;
        server_name _;
        root /usr/syno/synoman;
        include conf.d/dsm.*.conf;
        location = / { try_files $uri /index.cgi; }
    }
    server {
        listen 5001 default_server ssl;
        listen [::]:5001 default_server ssl;
        server_name _;
        include conf.d/ssl.*.conf;
        root /usr/syno/synoman;
        include conf.d/dsm.*.conf;
    }
    server {
        listen 80 default_server;
        server_name _;
        root /var/tmp/nginx/html;
        include conf.d/www.*.conf;
    }
    server {
        listen 443 default_server ssl;
        server_name _;
        root /var/tmp/nginx/html;
    }
}
`

func TestDetectSynologyEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		conf       string
		wantScheme string
		wantPort   int
		wantOK     bool
	}{
		{"real dsm config", nginxFixtureReal, "https", 5001, true},
		{"custom ssl port", `server { root /usr/syno/synoman; listen 8443 default_server ssl; }`, "https", 8443, true},
		{"addr qualified", `server { root /usr/syno/synoman; listen 127.0.0.1:7001 ssl; }`, "https", 7001, true},
		{"wildcard addr", `server { root /usr/syno/synoman; listen *:9001 ssl; }`, "https", 9001, true},
		{"ipv6 only", `server { root /usr/syno/synoman; listen [::]:5001 ssl; }`, "https", 5001, true},
		{"http only", `server { root /usr/syno/synoman; listen 5000 default_server; }`, "http", 5000, true},
		{"nonssl before ssl same port", `server { root /usr/syno/synoman; listen 6001; listen 6001 ssl; }`, "https", 6001, true},
		{"comment brace", "server { root /usr/syno/synoman; # a stray } brace\n listen 5001 ssl; }", "https", 5001, true},
		{"portal only no synoman", `server { root /var/tmp/nginx/html; listen 443 default_server ssl; }`, "https", 5001, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := dir + "/nginx.conf"
			if err := os.WriteFile(path, []byte(tt.conf), 0o600); err != nil {
				t.Fatal(err)
			}
			got := detectSynologyEndpoint(path)
			if got.Scheme != tt.wantScheme || got.Port != tt.wantPort || got.Detected != tt.wantOK {
				t.Fatalf("got %+v, want {%s %d %v}", got, tt.wantScheme, tt.wantPort, tt.wantOK)
			}
		})
	}
}

func TestDetectSynologyEndpoint_MissingFile(t *testing.T) {
	got := detectSynologyEndpoint(t.TempDir() + "/nope.conf")
	if got.Detected || got.Scheme != "https" || got.Port != 5001 {
		t.Fatalf("missing file should default: got %+v", got)
	}
}
