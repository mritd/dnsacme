package main

import (
	"bytes"
	"context"
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
		var hook string
		switch event {
		case "cert_obtaining":
			hook = conf.ObtainingHook
		case "cert_obtained":
			hook = conf.ObtainedHook
		case "cert_failed":
			hook = conf.FailedHook
		default:
			return nil
		}

		if hook == "" {
			return nil
		}

		env := os.Environ()
		oid := data["identifier"]
		storage := &certmagic.FileStorage{Path: conf.StorageDir}
		identifier := oid.(string)
		if identifier != "" {
			env = append(env, "ACME_IDENTIFIER="+identifier)
			domain := strings.Replace(identifier, "*", "wildcard_", 1)
			ss, err := storage.List(context.Background(), filepath.Join("certificates"), true)
			if err != nil {
				logrus.Fatalf("failed to list domain [%s] cert files: %v", identifier, err)
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
