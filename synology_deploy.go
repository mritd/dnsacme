package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// synologyHTTPClient remains replaceable so deployment behavior can be tested
// without reaching a real DSM instance.
var synologyHTTPClient = &http.Client{Timeout: 60 * time.Second}

// synologyAPIClient carries the SID and CSRF token returned by one DSM login.
// Both values are required by certificate import endpoints on DSM 7.
type synologyAPIClient struct {
	baseURL  string
	account  string
	password string
	sid      string
	token    string
	client   *http.Client
}

// deploySynologyCertificate loads CertMagic's files, separates the leaf from its
// intermediates, and imports the resulting multipart payload into DSM.
func deploySynologyCertificate(ctx context.Context, cfg SynologyDeployConfig, keyPath, certPath string) error {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	fullchain, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	leaf, intermediate, err := splitCertificateChain(fullchain)
	if err != nil {
		return err
	}

	client := newSynologyAPIClient(cfg)
	if err := client.login(ctx); err != nil {
		return err
	}
	defer func() { _ = client.logout(context.Background()) }()

	return client.importCertificate(ctx, cfg.CertificateDesc, cfg.Create, cfg.AsDefault, keyPEM, leaf, intermediate)
}

// verifySynologyLogin proves that the DSM endpoint accepts the configured account
// without importing anything. It is used by test-run and as an apply preflight;
// accounts that require an interactive OTP are not supported by this flow.
func verifySynologyLogin(ctx context.Context, cfg SynologyDeployConfig) error {
	client := newSynologyAPIClient(cfg)
	if err := client.login(ctx); err != nil {
		return err
	}
	_ = client.logout(context.Background())
	return nil
}

func newSynologyAPIClient(cfg SynologyDeployConfig) *synologyAPIClient {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Port
	if port == 0 {
		if scheme == "https" {
			port = 5001
		} else {
			port = 5000
		}
	}
	httpClient := synologyHTTPClient
	if scheme == "https" && strings.EqualFold(host, "127.0.0.1") {
		// DSM commonly serves a certificate whose names do not include the loopback
		// address. Limit verification bypass to the literal local endpoint; remote
		// hosts continue using the default verified transport.
		httpClient = &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
		}
	}
	return &synologyAPIClient{
		baseURL:  fmt.Sprintf("%s://%s:%d", scheme, host, port),
		account:  cfg.Account,
		password: cfg.Password,
		client:   httpClient,
	}
}

func (c *synologyAPIClient) login(ctx context.Context) error {
	values := url.Values{
		"api":     {"SYNO.API.Auth"},
		"version": {"6"},
		"method":  {"login"},
		"account": {c.account},
		"passwd":  {c.password},
		"session": {"Core"},
		"format":  {"sid"},
		// Package automation cannot prompt for a rotating OTP.
		"otp_code": {""},
		// The certificate APIs require SynoToken in addition to the session SID.
		"enable_syno_token": {"yes"},
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			SID       string `json:"sid"`
			SynoToken string `json:"synotoken"`
		} `json:"data"`
		Error synologyAPIError `json:"error"`
	}
	if err := c.postForm(ctx, "/webapi/auth.cgi", values, &result); err != nil {
		return err
	}
	if !result.Success || result.Data.SID == "" || result.Data.SynoToken == "" {
		return fmt.Errorf("Synology auth failed: %s", result.Error)
	}
	c.sid = result.Data.SID
	c.token = result.Data.SynoToken
	return nil
}

func (c *synologyAPIClient) logout(ctx context.Context) error {
	if c.sid == "" {
		return nil
	}
	values := url.Values{
		"api":     {"SYNO.API.Auth"},
		"version": {"6"},
		"method":  {"logout"},
		"session": {"Core"},
		"_sid":    {c.sid},
	}
	var result struct {
		Success bool `json:"success"`
	}
	return c.postForm(ctx, "/webapi/auth.cgi", values, &result)
}

// importCertificate follows DSM's established deployment contract: resolve an
// existing certificate by description and replace it, or create one when
// explicitly allowed. asDefault changes DSM's system-wide default certificate.
func (c *synologyAPIClient) importCertificate(ctx context.Context, desc string, create, asDefault bool, keyPEM, certPEM, intermediatePEM []byte) error {
	certID, found, err := c.certificateIDByDescription(ctx, desc)
	if err != nil {
		return err
	}
	if !found && !create {
		return fmt.Errorf("Synology certificate %q was not found", desc)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fields := map[string]string{
		"desc": desc,
		"id":   certID,
	}
	if asDefault {
		fields["as_default"] = "true"
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	if err := writeMultipartFile(writer, "key", "privkey.pem", keyPEM); err != nil {
		return err
	}
	if err := writeMultipartFile(writer, "cert", "cert.pem", certPEM); err != nil {
		return err
	}
	if len(intermediatePEM) > 0 {
		if err := writeMultipartFile(writer, "inter_cert", "chain.pem", intermediatePEM); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}

	query := url.Values{
		"api":       {"SYNO.Core.Certificate"},
		"version":   {"1"},
		"method":    {"import"},
		"SynoToken": {c.token},
		"_sid":      {c.sid},
	}
	// The URL contains SID and SynoToken and must never be written to logs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/webapi/entry.cgi?"+query.Encode(), &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// DSM accepts the token in the query on older builds and requires the header
	// on newer builds, so send both forms together with the SID.
	req.Header.Set("X-SYNO-TOKEN", c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		// The request URL carries the SID and SynoToken, and Go's *url.Error
		// stringifies that full URL. Never surface it: return only the transport
		// cause with a secret-free target so a transient network failure cannot
		// write the live session id and CSRF token into the package log.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("Synology certificate import request to %s/webapi/entry.cgi failed: %w", c.baseURL, urlErr.Err)
		}
		return fmt.Errorf("Synology certificate import request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Synology API returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Success bool             `json:"success"`
		Error   synologyAPIError `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("Synology certificate import failed: %s", result.Error)
	}
	return nil
}

// certificateIDByDescription uses an exact description match to avoid replacing
// an unrelated certificate with a similar label.
func (c *synologyAPIClient) certificateIDByDescription(ctx context.Context, desc string) (string, bool, error) {
	values := url.Values{
		"api":     {"SYNO.Core.Certificate.CRT"},
		"version": {"1"},
		"method":  {"list"},
		"_sid":    {c.sid},
	}
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Certificates []struct {
				ID   string `json:"id"`
				Desc string `json:"desc"`
			} `json:"certificates"`
		} `json:"data"`
		Error synologyAPIError `json:"error"`
	}
	if err := c.postForm(ctx, "/webapi/entry.cgi", values, &result); err != nil {
		return "", false, err
	}
	if !result.Success {
		return "", false, fmt.Errorf("Synology certificate list failed: %s", result.Error)
	}
	for _, cert := range result.Data.Certificates {
		if cert.Desc == desc {
			return cert.ID, true, nil
		}
	}
	return "", false, nil
}

func (c *synologyAPIClient) postForm(ctx context.Context, path string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("X-SYNO-TOKEN", c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Synology API returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type synologyAPIError struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

func (e synologyAPIError) String() string {
	if e.Code == 0 && e.Text == "" {
		return "unknown error"
	}
	if e.Text == "" {
		return fmt.Sprintf("code %d", e.Code)
	}
	return fmt.Sprintf("%s (code %d)", e.Text, e.Code)
}

func writeMultipartFile(writer *multipart.Writer, field, filename string, data []byte) error {
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, bytes.NewReader(data))
	return err
}

// splitCertificateChain maps CertMagic's fullchain format to DSM's separate leaf
// and intermediate upload fields. The first certificate is the requested leaf.
func splitCertificateChain(fullchain []byte) ([]byte, []byte, error) {
	var leaf bytes.Buffer
	var intermediate bytes.Buffer
	remaining := fullchain
	count := 0
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		count++
		target := &intermediate
		if count == 1 {
			target = &leaf
		}
		if err := pem.Encode(target, block); err != nil {
			return nil, nil, err
		}
	}
	if count == 0 {
		return nil, nil, errors.New("certificate file does not contain a PEM certificate")
	}
	return leaf.Bytes(), intermediate.Bytes(), nil
}
