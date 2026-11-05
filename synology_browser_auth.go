//go:build synology

package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// Browser authorization is deliberately separate from the deployment account.
// DSM's launcher visibility does not protect direct package CGI requests.
type synologyBrowserAuth struct {
	run        func(context.Context, string, []string, ...string) ([]byte, error)
	adminGroup func() (string, error)
}

func nativeSynologyBrowserAuth() synologyBrowserAuth {
	return synologyBrowserAuth{
		run: func(ctx context.Context, path string, env []string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, path, args...)
			cmd.Env = env
			return cmd.Output()
		},
		adminGroup: func() (string, error) {
			group, err := user.LookupGroup("administrators")
			if err != nil {
				return "", err
			}
			return group.Gid, nil
		},
	}
}

// verify invokes DSM's documented session validator with the original CGI
// context, then checks the authenticated account's actual group membership.
// Neither REMOTE_USER nor any caller-provided username is an identity source.
func (a synologyBrowserAuth) verify(ctx context.Context, getenv cgiEnv) (string, string, int, error) {
	r := &http.Request{Header: http.Header{"Cookie": []string{getenv("HTTP_COOKIE")}}}
	var sid string
	for _, cookie := range r.Cookies() {
		if cookie.Name == "id" {
			if sid != "" || cookie.Value == "" {
				return "", "", 401, errors.New("DSM sign-in required")
			}
			sid = cookie.Value
		}
	}
	if sid == "" {
		return "", "", 401, errors.New("DSM sign-in required")
	}
	env := []string{"PATH=/usr/bin:/bin", "LANG=C"}
	for _, key := range []string{"HTTP_COOKIE", "REMOTE_ADDR", "REMOTE_PORT", "SERVER_ADDR", "SERVER_PORT", "SERVER_PROTOCOL", "HTTPS", "HTTP_HOST", "HTTP_X_SYNO_TOKEN", "HTTP_X_REAL_IP", "QUERY_STRING", "REQUEST_METHOD", "SCRIPT_NAME", "SCRIPT_FILENAME", "REQUEST_URI"} {
		if value := getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := a.run(ctx, "/usr/syno/synoman/webman/modules/authenticate.cgi", env)
	name := strings.TrimSpace(string(output))
	if err != nil || name == "" || len(name) > 256 || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "\x00\r\n\t") {
		return "", "", 401, errors.New("DSM sign-in required")
	}
	group, err := a.adminGroup()
	if err != nil {
		return "", "", 403, errors.New("DSM administrator access required")
	}
	groups, err := a.run(ctx, "/bin/id", []string{"PATH=/usr/bin:/bin", "LANG=C"}, "-G", name)
	if err == nil {
		for _, gid := range strings.Fields(string(groups)) {
			if gid == group {
				return name, sid, 200, nil
			}
		}
	}
	return "", "", 403, errors.New("DSM administrator access required")
}

// A package-private key makes tokens stable across short-lived CGI processes.
// The HMAC is bound to both the verified username and the browser's DSM session.
// The bootstrap response is same-origin, never CORS enabled, and never cached.
func synologyBrowserCSRF(configPath, name, sid string) (string, error) {
	path := configPath + ".browser-csrf"
	var key []byte
	err := withSynologyConfigLock(configPath, func() error {
		var err error
		key, err = os.ReadFile(path)
		if err == nil {
			if len(key) != 32 {
				return errors.New("invalid CSRF key")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".browser-csrf-*")
		if err != nil {
			return err
		}
		defer os.Remove(file.Name())
		if _, err = file.Write(key); err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		preserveFileOwnership(file.Name(), configPath)
		return os.Rename(file.Name(), path)
	})
	if err != nil {
		return "", errors.New("browser security state unavailable")
	}

	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d:%s:%s", len(name), name, sid)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
