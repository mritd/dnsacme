//go:build synology

package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SynologyEndpoint is the detected local DSM WebAPI endpoint.
type SynologyEndpoint struct {
	Scheme   string `json:"scheme"`
	Port     int    `json:"port"`
	Detected bool   `json:"detected"`
}

// nginxConfPath returns the DSM nginx config path, overridable for tests.
func nginxConfPath() string {
	if p := os.Getenv("DNSACME_NGINX_CONF"); p != "" {
		return p
	}
	return "/etc/nginx/nginx.conf"
}

var (
	nginxCommentRe    = regexp.MustCompile(`#[^\n]*`)
	nginxServerOpenRe = regexp.MustCompile(`\bserver\s*\{`)
	nginxListenRe     = regexp.MustCompile(`\blisten\s+([^;{}]+);`)
	nginxPortRe       = regexp.MustCompile(`(?:.*:)?(\d+)$`)
)

type listenEntry struct {
	port int
	ssl  bool
}

// detectSynologyEndpoint parses DSM's nginx config and falls back to the standard
// HTTPS endpoint. A read failure is expected under some AppArmor profiles, so
// detection must remain advisory and never block manual host/port entry. Only
// synoman server blocks participate; HTTPS wins, otherwise the first HTTP listen
// entry from the generated config is used.
func detectSynologyEndpoint(path string) SynologyEndpoint {
	out := SynologyEndpoint{Scheme: "https", Port: 5001}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var entries []listenEntry
	for _, block := range extractServerBlocks(string(data)) {
		if !strings.Contains(block, "root /usr/syno/synoman") {
			continue
		}
		entries = append(entries, blockListens(block)...)
	}
	for _, e := range entries {
		if e.ssl {
			return SynologyEndpoint{Scheme: "https", Port: e.port, Detected: true}
		}
	}
	if len(entries) > 0 {
		return SynologyEndpoint{Scheme: "http", Port: entries[0].port, Detected: true}
	}
	return out
}

// extractServerBlocks performs only brace matching needed for DSM's generated
// nginx file; it is not intended to be a general-purpose nginx parser.
func extractServerBlocks(s string) []string {
	s = nginxCommentRe.ReplaceAllString(s, "")
	var blocks []string
	for _, loc := range nginxServerOpenRe.FindAllStringIndex(s, -1) {
		open := loc[1] - 1
		depth := 0
		for j := open; j < len(s); j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					blocks = append(blocks, s[open+1:j])
					j = len(s)
				}
			}
		}
	}
	return blocks
}

func blockListens(block string) []listenEntry {
	var out []listenEntry
	seen := map[listenEntry]struct{}{}
	for _, m := range nginxListenRe.FindAllStringSubmatch(block, -1) {
		fields := strings.Fields(m[1])
		if len(fields) == 0 {
			continue
		}
		pm := nginxPortRe.FindStringSubmatch(fields[0])
		if pm == nil {
			continue
		}
		port, err := strconv.Atoi(pm[1])
		if err != nil {
			continue
		}
		entry := listenEntry{port: port}
		for _, f := range fields[1:] {
			if f == "ssl" {
				entry.ssl = true
			}
		}
		if _, ok := seen[entry]; ok {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}
