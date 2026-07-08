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

// OnEvent Run the event hook when CertMagic obtain a certificate
// hook must be re-executable (idempotent), because it may be called multiple times
func OnEvent(conf *Config) func(ctx context.Context, event string, data map[string]any) error {
	return func(ctx context.Context, event string, data map[string]any) error {
		hook := hookForEvent(conf, event)
		if hook == "" {
			return nil
		}

		env, err := hookEnv(ctx, conf, data)
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		cmd := exec.Command(hook)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		cmd.Env = env

		if err := cmd.Run(); err != nil {
			logrus.Errorf("cmd hook run failed: %v", err)
		}
		logrus.Infof("cmd hook command: %s\n============ CMD HOOK LOG BEGIN ============\n%s\n============ CMD HOOK LOG END ==============", hook, buf.String())
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
			if strings.HasSuffix(s, domain+".key") {
				env = append(env, "ACME_KEY_PATH="+filepath.Join(conf.StorageDir, s))
			}
			if strings.HasSuffix(s, domain+".crt") {
				env = append(env, "ACME_CERT_PATH="+filepath.Join(conf.StorageDir, s))
			}
		}
	}
	return env, nil
}

func certStorageName(identifier string) string {
	return strings.Replace(identifier, "*.", "wildcard_", 1)
}
