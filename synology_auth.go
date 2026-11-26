//go:build synology

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const synologyAuthCheckInterval = 24 * time.Hour
const synologyDeployRetryInterval = time.Hour

// DSM authentication errors have a safe, actionable description. Do not echo
// server-supplied text: it may contain values from the credential-bearing request.
type synologyAuthError struct{ Code int }

func (e *synologyAuthError) Error() string {
	switch e.Code {
	case 403, 404, 406:
		return "Synology auth failed: reauthentication required; open DNSACME and sign in with a fresh OTP"
	case 400, 401, 402, 407, 408, 409, 410:
		return fmt.Sprintf("Synology auth failed: check the DSM account/password or account restrictions (code %d); sign in again in DNSACME", e.Code)
	default:
		return fmt.Sprintf("Synology auth failed (code %d)", e.Code)
	}
}
func synologyAuthNeedsInput(err error) bool {
	var authErr *synologyAuthError
	if !errors.As(err, &authErr) {
		return false
	}
	switch authErr.Code {
	case 400, 401, 402, 403, 404, 406, 407, 408, 409, 410:
		return true
	}
	return false
}

// This file lives beside config.yaml and has the same private ownership/mode.
// Keeping operational authentication outside the form configuration preserves
// legacy ConfigHash values and avoids invalidating editor tokens on health checks.
// OTPs, TOTP seeds, recovery codes, SIDs and CSRF tokens are never persisted.
type synologyAuthState struct {
	Identity        string    `json:"identity"`
	DeviceID        string    `json:"deviceID,omitempty"`
	DeviceName      string    `json:"deviceName,omitempty"`
	Status          string    `json:"status,omitempty"`
	Message         string    `json:"message,omitempty"`
	CheckedAt       time.Time `json:"checkedAt"`
	DeploymentHash  string    `json:"deploymentHash,omitempty"`
	Pending         bool      `json:"pending"`
	DeploymentError string    `json:"deploymentError,omitempty"`
	DeployAttemptAt time.Time `json:"deployAttemptAt"`
	DeployedAt      time.Time `json:"deployedAt"`
}

func synologyAuthIdentity(cfg SynologyDeployConfig) string {
	data, _ := json.Marshal(struct {
		Scheme, Host, Account, Password string
		Port                            int
	}{cfg.Scheme, cfg.Host, cfg.Account, cfg.Password, cfg.Port})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func synologyAuthPath(configPath string) string { return synologyConfigPath(configPath) + ".auth.json" }
func loadSynologyAuth(configPath string, cfg SynologyConfig) (synologyAuthState, error) {
	identity := synologyAuthIdentity(cfg.Synology)
	state := synologyAuthState{Identity: identity}
	data, err := os.ReadFile(synologyAuthPath(configPath))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, errors.New("cannot read DSM authentication state")
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, errors.New("invalid DSM authentication state")
	}
	if state.Identity != identity {
		return synologyAuthState{Identity: identity}, nil
	}
	if state.DeploymentHash != cfg.ConfigHash() {
		state.Pending = false
		state.DeploymentError = ""
		state.DeployAttemptAt = time.Time{}
		state.DeployedAt = time.Time{}
	}
	return state, nil
}

// An independent lock serializes DSM logins across CGI tasks and the daemon.
// Unlike the short config lock, it deliberately covers the bounded DSM request.
func withSynologyAuthLock(configPath string, fn func() error) error {
	path := synologyAuthPath(configPath)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	preserveFileOwnership(path+".lock", synologyConfigPath(configPath))
	if err := lockSynologyConfig(lock); err != nil {
		return errors.New("DSM authentication is busy; try again shortly")
	}
	defer unlockSynologyConfig(lock)
	return fn()
}

func saveSynologyAuth(configPath string, cfg SynologyConfig, state synologyAuthState) error {
	return withSynologyConfigLock(configPath, func() error {
		current, err := loadSynologyConfig(configPath)
		if err != nil {
			return err
		}
		if current.ConfigHash() != cfg.ConfigHash() {
			return errSynologyConfigChanged
		}
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		path := synologyAuthPath(configPath)
		f, err := os.CreateTemp(filepath.Dir(path), ".dsm-auth-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		if _, err = f.Write(data); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		preserveFileOwnership(f.Name(), synologyConfigPath(configPath))
		return os.Rename(f.Name(), path)
	})
}

func synologyAuthView(configPath string, cfg SynologyConfig) map[string]any {
	state, err := loadSynologyAuth(configPath, cfg)
	if err != nil {
		return map[string]any{"status": "error", "message": err.Error()}
	}
	status := state.Status
	if status == "" {
		status = "unchecked"
	}
	return map[string]any{
		"status": status, "message": state.Message, "checkedAt": state.CheckedAt,
		"trustedDevice": state.DeviceID != "", "deviceName": state.DeviceName,
		"deploymentPending": state.Pending, "deploymentError": state.DeploymentError,
		"deployedAt": state.DeployedAt,
	}
}

var notifySynologyAuthentication = func(ctx context.Context, message string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// synodsmnotify is DSM's notification helper. No credentials or remote
	// response bodies enter the notification or its command-line arguments.
	return exec.CommandContext(ctx, "/usr/syno/bin/synodsmnotify", "@administrators", "DNSACME", message).Run()
}

func notifySynologyAttention(ctx context.Context, cfg SynologyConfig, message string) {
	if err := notifySynologyAuthentication(ctx, message); err != nil {
		appendSynologyLog(cfg, "DSM notification could not be delivered; open DNSACME to check authentication/deployment status")
	}
}

// interactive is true only for the explicit sign-in action. A rejected password
// or trusted device blocks unattended retries until that action succeeds.
func runSynologyDSMOperation(ctx context.Context, configPath string, cfg SynologyConfig, otp, deviceName string, interactive bool, deploy func(*synologyAPIClient) error) error {
	cfg = normalizeSynologyConfig(cfg)
	return withSynologyAuthLock(configPath, func() error {
		state, err := loadSynologyAuth(configPath, cfg)
		if err != nil {
			return err
		}
		previousStatus, previousPending := state.Status, state.Pending
		if deploy != nil {
			state.Pending = true
			state.DeploymentHash = cfg.ConfigHash()
			state.DeployAttemptAt = time.Now()
			state.DeploymentError = "Certificate deployment is pending"
			if err := saveSynologyAuth(configPath, cfg, state); err != nil {
				return err
			}
		}
		if state.Status == "reauth_required" && !interactive {
			return errors.New(state.Message)
		}
		deployCfg := cfg.Synology
		deployCfg.DeviceID, deployCfg.DeviceName = state.DeviceID, state.DeviceName
		client := newSynologyAPIClient(deployCfg)
		err = client.loginWithOTP(ctx, otp, deviceName)
		state.CheckedAt = time.Now()
		if err != nil {
			state.Status, state.Message = "error", err.Error()
			if synologyAuthNeedsInput(err) {
				state.Status = "reauth_required"
			}
			if saveErr := saveSynologyAuth(configPath, cfg, state); saveErr != nil {
				return saveErr
			}
			if state.Status == "reauth_required" && previousStatus != state.Status {
				notifySynologyAttention(ctx, cfg, "DSM sign-in needs your attention. Open DNSACME and sign in again before the certificate expires.")
			}
			return err
		}
		defer func() {
			logoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = client.logout(logoutCtx)
		}()
		state.DeviceID, state.DeviceName = client.deviceID, client.deviceName
		state.Status, state.Message = "ready", "DSM sign-in succeeded"
		if interactive {
			state.DeployAttemptAt = time.Time{}
		}
		if deploy != nil {
			state.Pending = true
			state.DeploymentHash = cfg.ConfigHash()
			state.DeployAttemptAt = time.Now()
		}
		// Persist a newly issued/rotated device credential before any import.
		if err := saveSynologyAuth(configPath, cfg, state); err != nil {
			return err
		}
		if deploy == nil {
			return nil
		}
		err = deploy(client)
		if err != nil {
			state.DeploymentError = "DSM certificate import failed; check DNSACME logs and DSM account permissions"
		} else {
			state.Pending, state.DeploymentError = false, ""
			state.DeployedAt = time.Now()
		}
		if saveErr := saveSynologyAuth(configPath, cfg, state); saveErr != nil {
			return saveErr
		}
		if err != nil && !previousPending {
			notifySynologyAttention(ctx, cfg, "A certificate was issued but could not be installed in DSM. Open DNSACME to review the deployment failure.")
		}
		return err
	})
}

func verifySynologyConfiguredLogin(ctx context.Context, configPath string, cfg SynologyConfig) error {
	return runSynologyDSMOperation(ctx, configPath, cfg, "", "", false, nil)
}

func cgiSynologyAuthenticate(ctx context.Context, method, configPath string, input io.Reader) (any, error) {
	if method != http.MethodPost {
		return nil, fmt.Errorf("method %s is not allowed", method)
	}
	var req struct {
		EditToken  string `json:"editToken"`
		OTP        string `json:"otp"`
		DeviceName string `json:"deviceName"`
	}
	if err := json.NewDecoder(io.LimitReader(input, 4096)).Decode(&req); err != nil {
		return nil, errors.New("invalid DSM sign-in request")
	}
	if req.OTP != "" {
		if len(req.OTP) != 6 {
			return nil, errors.New("enter a six-digit OTP")
		}
		for _, c := range req.OTP {
			if c < '0' || c > '9' {
				return nil, errors.New("enter a six-digit OTP")
			}
		}
	}
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	if req.DeviceName == "" {
		req.DeviceName = "DNSACME"
	}
	if len(req.DeviceName) > 64 || strings.ContainsAny(req.DeviceName, "\r\n\x00") {
		return nil, errors.New("invalid device name")
	}
	snapshot, err := loadSynologyConfigSnapshot(configPath)
	if err != nil {
		return nil, err
	}
	if req.EditToken == "" || req.EditToken != snapshot.EditToken {
		return nil, errSynologyConfigChanged
	}
	cfg := snapshot.Config
	if cfg.Synology.Account == "" || cfg.Synology.Password == "" {
		return nil, errors.New("save the DSM account and password before signing in")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	err = runSynologyDSMOperation(ctx, configPath, cfg, req.OTP, req.DeviceName, true, nil)
	req.OTP = ""
	return synologyAuthView(configPath, cfg), err
}

// Check trusted-device access daily, well before an ACME renewal is due. Failed
// imports are retried from existing certificate storage (never reissued) hourly.
func maintainSynologyAuthentication(ctx context.Context, configPath string, cfg SynologyConfig) {
	state, err := loadSynologyAuth(configPath, cfg)
	if err != nil {
		appendSynologyLog(cfg, err.Error())
		return
	}
	if state.Status == "reauth_required" {
		return
	}
	if state.Pending && time.Since(state.DeployAttemptAt) >= synologyDeployRetryInterval {
		key, cert, err := findStoredCertificate(ctx, cfg.Runtime.StorageDir, firstSynologyIdentifier(cfg))
		if err != nil {
			return
		}
		_ = deploySynologyStoredCertificate(ctx, cfg, firstSynologyIdentifier(cfg), key, cert, configPath)
		return
	}
	interval := synologyAuthCheckInterval
	if state.Status == "error" {
		interval = synologyDeployRetryInterval
	}
	if state.DeviceID != "" && time.Since(state.CheckedAt) >= interval {
		if err := verifySynologyConfiguredLogin(ctx, configPath, cfg); err != nil {
			appendSynologyLog(cfg, "DSM authentication check failed: "+err.Error())
		}
	}
}
