//go:build synology

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testBrowserAuth(name, groups string) synologyBrowserAuth {
	return synologyBrowserAuth{
		run: func(_ context.Context, path string, _ []string, _ ...string) ([]byte, error) {
			if path == "/bin/id" {
				return []byte(groups), nil
			}
			return []byte(name), nil
		},
		adminGroup: func() (string, error) { return "101", nil },
	}
}

// Existing business-flow tests inject an authenticated administrator explicitly.
// Production dispatch always uses the native validator, with no bypass setting.
func serveTestSynologyCGI(ctx context.Context, path string, getenv cgiEnv, input io.Reader, output io.Writer) error {
	token, err := synologyBrowserCSRF(path, "admin", "test-session")
	if err != nil {
		return err
	}
	env := func(key string) string {
		switch key {
		case "HTTP_COOKIE":
			return "id=test-session"
		case "HTTP_X_DNSACME_CSRF":
			return token
		case "CONTENT_TYPE":
			return "application/json"
		default:
			return getenv(key)
		}
	}
	return serveSynologyCGIWithAuth(ctx, path, env, input, output, testBrowserAuth("admin", "100 101"))
}

type unreadableBody struct{ read bool }

func (r *unreadableBody) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("must not read body")
}

func TestBrowserAuthorizationAllCGIActions(t *testing.T) {
	actions := []string{"config", "reconfigure", "acmedns-register", "authenticate", "auth-status", "metadata", "status", "logs", "test-run", "apply", "csrf", "unknown"}
	for _, action := range actions {
		for _, alias := range []bool{false, true} {
			for _, method := range []string{"GET", "POST", "PUT"} {
				for _, denied := range []struct {
					name, cookie, user, groups, token string
					status                            string
				}{
					{"anonymous", "", "admin", "101", "", "401"},
					{"forged identity", "id=fake", "", "101", "", "401"},
					{"non-admin", "id=valid", "ordinary", "100", "", "403"},
					{"missing CSRF", "id=valid", "admin", "101", "", "403"},
					{"wrong CSRF", "id=valid", "admin", "101", "wrong", "403"},
					{"duplicate session", "id=valid; id=another", "admin", "101", "", "401"},
				} {
					if action == "csrf" && method == "GET" && strings.Contains(denied.name, "CSRF") {
						continue
					}
					t.Run(action+"/"+method+"/"+denied.name+map[bool]string{true: "/path", false: "/query"}[alias], func(t *testing.T) {
						path := filepath.Join(t.TempDir(), "config.yaml")
						env := func(k string) string {
							switch k {
							case "REQUEST_METHOD":
								return method
							case "QUERY_STRING":
								if !alias {
									return "action=" + action
								}
							case "PATH_INFO":
								if alias {
									return "/" + action
								}
							case "HTTP_COOKIE":
								return denied.cookie
							case "HTTP_X_DNSACME_CSRF":
								return denied.token
							case "REMOTE_USER":
								return "admin"
							case "CONTENT_TYPE":
								return "application/json"
							}
							return ""
						}
						body := &unreadableBody{}
						var out bytes.Buffer
						if err := serveSynologyCGIWithAuth(context.Background(), path, env, body, &out, testBrowserAuth(denied.user, denied.groups)); err != nil {
							t.Fatal(err)
						}
						if !strings.HasPrefix(out.String(), "Status: "+denied.status) || body.read || strings.Contains(out.String(), "editToken") {
							t.Fatalf("denied request reached handler: %s", out.String())
						}
						if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
							t.Fatal("config was touched")
						}
					})
				}
			}
		}
	}
}

func TestBrowserCSRFSessionBindingAndLegitimateRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	one, err := synologyBrowserCSRF(path, "admin", "one")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := synologyBrowserCSRF(path, "admin", "one")
	two, _ := synologyBrowserCSRF(path, "admin", "two")
	other, _ := synologyBrowserCSRF(path, "other", "one")
	if one != again || one == two || one == other {
		t.Fatal("CSRF not bound to session and account")
	}
	info, _ := os.Stat(path + ".browser-csrf")
	if info.Mode().Perm() != 0600 {
		t.Fatal("CSRF key is not private")
	}
	var out bytes.Buffer
	if err := serveTestSynologyCGI(context.Background(), path, queryEnv("action=config", "GET"), strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if !parseCGIResponse(t, out.String()).Success {
		t.Fatal("legitimate config read failed")
	}
}

func TestBrowserRejectsFormJSONAndUnavailableValidator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	token, _ := synologyBrowserCSRF(path, "admin", "one")
	env := func(k string) string {
		return map[string]string{"HTTP_COOKIE": "id=one", "HTTP_X_DNSACME_CSRF": token, "REQUEST_METHOD": "POST", "QUERY_STRING": "action=config", "CONTENT_TYPE": "text/plain"}[k]
	}
	var out bytes.Buffer
	_ = serveSynologyCGIWithAuth(context.Background(), path, env, &unreadableBody{}, &out, testBrowserAuth("admin", "101"))
	if !strings.HasPrefix(out.String(), "Status: 415") {
		t.Fatal(out.String())
	}
	auth := testBrowserAuth("admin", "101")
	auth.run = func(context.Context, string, []string, ...string) ([]byte, error) {
		return nil, errors.New("unavailable")
	}
	out.Reset()
	_ = serveSynologyCGIWithAuth(context.Background(), path, env, &unreadableBody{}, &out, auth)
	if !strings.HasPrefix(out.String(), "Status: 401") {
		t.Fatal("validator must fail closed")
	}
}

func TestBrowserCSRFFirstUseConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	var wg sync.WaitGroup
	results := make(chan string, 24)
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := synologyBrowserCSRF(path, "admin", "one")
			if err != nil {
				t.Error(err)
			}
			results <- token
		}()
	}
	wg.Wait()
	close(results)
	var first string
	for token := range results {
		if first == "" {
			first = token
		}
		if token == "" || token != first {
			t.Fatal("concurrent bootstrap produced inconsistent tokens")
		}
	}
}
