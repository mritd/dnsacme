package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// newSynologyCommand groups package lifecycle commands and the DSM CGI entry
// point without changing the normal standalone CLI workflow.
func newSynologyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "synology",
		Short: "Manage Synology DSM package integration",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "daemon",
		Short: "Run the long-lived Synology package certificate manager",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSynologyDaemon(cmd.Context(), configFile)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "test-run",
		Short: "Request a staging ACME certificate without deploying to DSM",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Minute)
			defer cancel()
			result, err := runSynologyTest(ctx, configFile)
			printJSON(result)
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "apply",
		Short: "Request a production ACME certificate and deploy it to DSM",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Minute)
			defer cancel()
			result, err := runSynologyApply(ctx, configFile)
			printJSON(result)
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:    "api-cgi",
		Short:  "Serve Synology DSM CGI API",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return serveSynologyCGI(cmd.Context(), configFile, os.Getenv, os.Stdin, os.Stdout)
		},
	})
	return cmd
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

type cgiEnv func(string) string

// serveSynologyCGI adapts DSM's same-origin CGI environment to a small JSON API.
// Read operations accept GET, while configuration writes and ACME operations
// require a mutating HTTP method so opening an app URL cannot change state. DSM's
// package-app access control is the authentication, authorization, and CSRF
// boundary; this internal CGI does not implement a second session protocol.
func serveSynologyCGI(ctx context.Context, configPath string, getenv cgiEnv, input io.Reader, output io.Writer) error {
	method := getenv("REQUEST_METHOD")
	if method == "" {
		method = http.MethodGet
	}
	values, _ := url.ParseQuery(getenv("QUERY_STRING"))
	action := values.Get("action")
	if action == "" {
		action = strings.TrimPrefix(getenv("PATH_INFO"), "/")
	}

	status := http.StatusOK
	var payload any
	var err error

	switch action {
	case "config":
		payload, err = cgiConfig(method, configPath, input)
	case "reconfigure":
		payload, err = cgiReconfigure(method, configPath)
	case "metadata":
		payload = map[string]any{"providers": providerMetadata()}
	case "status":
		payload, err = cgiStatus(configPath)
	case "logs":
		payload, err = cgiLogs(configPath)
	case "test-run":
		if method != http.MethodPost {
			status = http.StatusMethodNotAllowed
			err = fmt.Errorf("method %s is not allowed", method)
			break
		}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		defer cancel()
		payload, err = runSynologyTest(runCtx, configPath)
	case "apply":
		if method != http.MethodPost {
			status = http.StatusMethodNotAllowed
			err = fmt.Errorf("method %s is not allowed", method)
			break
		}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		defer cancel()
		payload, err = runSynologyApply(runCtx, configPath)
	default:
		status = http.StatusNotFound
		err = fmt.Errorf("unknown action: %s", action)
	}

	if err != nil && status == http.StatusOK {
		status = http.StatusBadRequest
	}
	return writeCGIJSON(output, status, payload, err)
}

func cgiConfig(method, configPath string, input io.Reader) (any, error) {
	current, err := loadSynologyConfig(configPath)
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		return synologyConfigResponse(current, configPath), nil
	}
	if method != http.MethodPost && method != http.MethodPut {
		return nil, fmt.Errorf("method %s is not allowed", method)
	}
	var next SynologyConfig
	if err := json.NewDecoder(input).Decode(&next); err != nil {
		return nil, err
	}
	// Runtime paths belong to the package installation, not the browser. Ignore
	// client-supplied values to keep config writes inside package-owned storage.
	next.Runtime = current.Runtime
	// Reconfiguration mode is controlled by its dedicated CGI action. Normal form
	// saves must preserve it until a production apply completes successfully.
	next.Reconfiguring = current.Reconfiguring
	// The UI only receives redacted values. A mask sentinel or an unchanged empty
	// secret means "keep the persisted value" rather than erase credentials.
	next = mergeSecrets(next, current)
	next = normalizeSynologyConfig(next)
	if next.ConfigHash() != current.ConfigHash() {
		next.LastTest = SynologyOperationState{}
		next.LastApply = SynologyOperationState{}
	} else {
		next.LastTest = current.LastTest
		next.LastApply = current.LastApply
	}
	if err := saveSynologyConfig(configPath, next); err != nil {
		return nil, err
	}
	return synologyConfigResponse(next, configPath), nil
}

// cgiReconfigure persists the user's decision to edit a deployed configuration.
// It deliberately leaves the certificate hash and last apply result unchanged,
// so merely opening the wizard cannot interrupt the active renewal manager.
func cgiReconfigure(method, configPath string) (any, error) {
	if method != http.MethodPost {
		return nil, fmt.Errorf("method %s is not allowed", method)
	}
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return nil, err
	}
	cfg.Reconfiguring = true
	// Re-entering the wizard does not erase an optional staging result when the
	// user keeps the configuration unchanged. ConfigHash invalidates it naturally
	// if a subsequent form save changes certificate inputs.
	if err := saveSynologyConfig(configPath, cfg); err != nil {
		return nil, err
	}
	return synologyConfigResponse(cfg, configPath), nil
}

func cgiStatus(configPath string) (any, error) {
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return nil, err
	}
	lastTest := cfg.LastTest
	lastTest.ConfigHash = ""
	lastApply := cfg.LastApply
	lastApply.ConfigHash = ""
	return map[string]any{
		"testPassed": cfg.TestPassed(),
		"canRenew":   cfg.CanRenew(),
		"lastTest":   lastTest,
		"lastApply":  lastApply,
		// Long-running apply requests can leave DSM's SCGI gateway unable to serve
		// the immediately following config request. Return the redacted config with
		// status so the UI's HTTP-0 reconciliation path can enter the deployed view
		// without issuing a second request.
		"config": cfg.Redacted(),
	}, nil
}

// maxLogLines bounds the response sent to the live UI. cgiLogs still reads the
// current file in full before selecting this tail.
const maxLogLines = 100

func cgiLogs(configPath string) (any, error) {
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(normalizeSynologyConfig(cfg).Runtime.LogPath)
	if os.IsNotExist(err) {
		return map[string]string{"logs": ""}, nil
	}
	if err != nil {
		return nil, err
	}
	return map[string]string{"logs": normalizeSynologyLogTimestamps(tailLines(string(data), maxLogLines))}, nil
}

// tailLines returns the last n lines of s, ignoring a trailing newline so the
// final blank line does not displace a real log line.
func tailLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	trimmed := strings.TrimRight(s, "\n")
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// normalizeSynologyLogTimestamps converts legacy CertMagic floating-point Unix
// timestamps while leaving already formatted logrus/RFC3339 lines untouched.
func normalizeSynologyLogTimestamps(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		seconds, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || seconds < 946684800 {
			continue
		}
		sec := int64(seconds)
		nsec := int64((seconds - float64(sec)) * float64(time.Second))
		lines[i] = time.Unix(sec, nsec).Local().Format(time.RFC3339) + "\t" + parts[1]
	}
	return strings.Join(lines, "\n")
}

// synologyConfigResponse is the only configuration shape returned to the UI;
// credentials and internal validation hashes are always redacted here.
func synologyConfigResponse(cfg SynologyConfig, configPath string) map[string]any {
	cfg = normalizeSynologyConfig(cfg)
	return map[string]any{
		"config":     cfg.Redacted(),
		"testPassed": cfg.TestPassed(),
		"canRenew":   cfg.CanRenew(),
		"persisted":  synologyConfigPersisted(configPath),
		"detected":   detectSynologyEndpoint(nginxConfPath()),
	}
}

// synologyConfigPersisted returns false only when the config is definitely
// absent. Other stat errors are treated as persisted so first-run endpoint
// detection cannot overwrite manual values on an indeterminate filesystem.
func synologyConfigPersisted(configPath string) bool {
	_, err := os.Stat(synologyConfigPath(configPath))
	if err == nil {
		return true
	}
	return !errors.Is(err, os.ErrNotExist)
}

// writeCGIJSON emits the CGI Status header and the stable response envelope
// consumed by DNSACME.js. no-store prevents browser caching of package state.
func writeCGIJSON(output io.Writer, status int, payload any, err error) error {
	response := map[string]any{
		"success": err == nil,
		"data":    payload,
	}
	if err != nil {
		response["error"] = err.Error()
	}
	data, encodeErr := json.Marshal(response)
	if encodeErr != nil {
		return encodeErr
	}
	fmt.Fprintf(output, "Status: %d %s\r\n", status, http.StatusText(status))
	fmt.Fprint(output, "Content-Type: application/json; charset=utf-8\r\n")
	fmt.Fprint(output, "Cache-Control: no-store\r\n\r\n")
	_, writeErr := output.Write(data)
	return writeErr
}
