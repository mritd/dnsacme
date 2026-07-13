package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/caddyserver/certmagic"

	"github.com/sirupsen/logrus"
)

// OnEvent dispatches the optional command hook first and then the in-process
// EventHook. Command failures remain log-only for backward compatibility;
// EventHook errors are returned to CertMagic, whose handling depends on the event
// phase. Every hook must be idempotent because events can be emitted repeatedly.
func OnEvent(conf *Config) func(ctx context.Context, event string, data map[string]any) error {
	return func(ctx context.Context, event string, data map[string]any) error {
		hook := hookForEvent(conf, event)
		if hook == "" {
			if conf.EventHook != nil {
				return conf.EventHook(ctx, event, data)
			}
			return nil
		}

		env, err := hookEnv(ctx, conf, data)
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		// Hook paths come from trusted local configuration and execute directly,
		// without a shell. They inherit the process environment plus certificate
		// paths, and their stdout/stderr is written verbatim to the application log.
		cmd := exec.Command(hook)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		cmd.Env = env

		if err := cmd.Run(); err != nil {
			logrus.Errorf("cmd hook run failed: %v", err)
		}
		logrus.Infof("cmd hook command: %s\n============ CMD HOOK LOG BEGIN ============\n%s\n============ CMD HOOK LOG END ==============", hook, buf.String())
		if conf.EventHook != nil {
			return conf.EventHook(ctx, event, data)
		}
		return nil
	}
}

func hookForEvent(conf *Config, event string) string {
	switch event {
	case "cert_obtaining":
		return conf.ObtainingHook
	case "cert_obtained":
		return conf.ObtainedHook
	case "cert_failed":
		return conf.FailedHook
	default:
		return ""
	}
}

func hookEnv(ctx context.Context, conf *Config, data map[string]any) ([]string, error) {
	env := os.Environ()
	oid, _ := data["identifier"]
	storage := &certmagic.FileStorage{Path: conf.StorageDir}
	identifier, _ := oid.(string)
	if identifier != "" {
		env = append(env, "ACME_IDENTIFIER="+identifier)
		domain := certStorageName(identifier)
		ss, err := storage.List(ctx, filepath.Join("certificates"), true)
		if err != nil {
			return nil, fmt.Errorf("failed to list domain [%s] cert files: %w", identifier, err)
		}

		for _, s := range ss {
			// Match the exact CertMagic leaf file (certificates/<ca>/<name>/<name>.crt),
			// not a suffix. A sibling identifier whose storage name ends with the
			// target's name — e.g. "sub.example.com" or "wildcard_.example.com" for
			// target "example.com" — would also satisfy HasSuffix(domain+".crt") and,
			// sorting later, win the last write, importing the wrong host's certificate.
			switch filepath.Base(s) {
			case domain + ".key":
				env = append(env, "ACME_KEY_PATH="+filepath.Join(conf.StorageDir, s))
			case domain + ".crt":
				env = append(env, "ACME_CERT_PATH="+filepath.Join(conf.StorageDir, s))
			}
		}
	}
	return env, nil
}

func certStorageName(identifier string) string {
	// CertMagic replaces the wildcard byte and preserves the following dot,
	// producing storage directories such as wildcard_.example.com.
	return strings.Replace(identifier, "*", "wildcard_", 1)
}
