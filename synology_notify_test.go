package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSynologyNotificationArgsUseSystemNotificationMode(t *testing.T) {
	args, err := synologyNotificationArgs("DNSACMECertDeployed", map[string]string{"%CERT_DOMAIN%": "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 3 || args[0] != "@administrators" || args[1] != "DNSACMECertDeployed" {
		t.Fatalf("unexpected synodsmnotify arguments: %v", args)
	}
	for _, arg := range args {
		if arg == "-c" || arg == "-t" || arg == "-l" {
			t.Fatalf("system notification must not mix direct desktop flags: %v", args)
		}
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(args[2]), &payload); err != nil {
		t.Fatalf("invalid notification payload: %v", err)
	}
	if payload["%CERT_DOMAIN%"] != "example.com" {
		t.Fatalf("certificate variable missing from payload: %v", payload)
	}
	if payload["DESKTOP_NOTIFY_CLASSNAME"] != synologyNotificationAppID {
		t.Fatalf("desktop class name missing from payload: %v", payload)
	}
}

// The notification templates are embedded in the binary and published to
// /var/cache/texts/DNSACME once by the root publish-notifications command. Every
// supported language must define the same event with the fields DSM's renderer
// expects, or a locale would silently fall back to the raw tag name in the tray.
func TestSynologyNotificationTemplatesDefineRenewedEvent(t *testing.T) {
	for _, lang := range []string{"enu", "chs"} {
		data, err := os.ReadFile(filepath.Join("synology", "spk", "notification", lang, "mails"))
		if err != nil {
			t.Fatal(err)
		}
		content := string(data)
		for _, marker := range []string{"[DNSACMECertRenewed]", "[DNSACMECertDeployed]", "Category: DNSACME", "Level: NOTIFICATION_INFO", "Title:", "Desktop:", "Subject:", "%CERT_DOMAIN%"} {
			if !strings.Contains(content, marker) {
				t.Fatalf("%s template is missing %q", lang, marker)
			}
		}
	}
}

// stubSynologyNotificationsPublished makes the delivery gate's published-catalog
// check pass so notification-sending tests do not need a real /var/cache/texts on
// the host. Callers still set cfg.NotificationsEnabled to satisfy the user intent
// half of the gate.
func stubSynologyNotificationsPublished(t *testing.T) {
	t.Helper()
	old := synologyNotificationTemplatesPresent
	synologyNotificationTemplatesPresent = func() bool { return true }
	t.Cleanup(func() { synologyNotificationTemplatesPresent = old })
}

func markSynologyNotificationCatalogRegistered(cfg *SynologyConfig) {
	cfg.NotificationCatalogRegistered = true
}

func TestSynologyRenewalDeployHookNotifiesOnlyOnSuccessfulImport(t *testing.T) {
	dir := t.TempDir()
	server := fakeSynologyServerWithCerts(t, map[string]string{"dnsacme": "cert-id-1"}, nil)
	u, _ := url.Parse(server.URL)
	host, port, _ := strings.Cut(u.Host, ":")

	cfg := validSynologyConfig(dir)
	cfg.Synology.Scheme = u.Scheme
	cfg.Synology.Host = host
	cfg.Synology.Port = atoiForTest(port)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	stubSynologyNotificationsPublished(t)
	writeStoredCert(t, cfg.Runtime.StorageDir, cfg.ACME.Domains[0])

	oldNotify := synologyNotifyCommand
	var notifications []string
	synologyNotifyCommand = func(ctx context.Context, tag string, vars map[string]string) error {
		notifications = append(notifications, tag)
		return nil
	}
	defer func() { synologyNotifyCommand = oldNotify }()

	hook := synologyRenewalDeployHook(cfg, cfg.Runtime.StorageDir)
	// Unrelated events must neither deploy nor notify.
	if err := hook(context.Background(), "cert_obtaining", map[string]any{"identifier": cfg.ACME.Domains[0]}); err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 0 {
		t.Fatalf("unexpected notification for a non-obtained event: %v", notifications)
	}
	// A manager starting against empty storage emits cert_obtained with renewal
	// false (or absent). It still deploys the certificate, but must not describe
	// that first deployment as a renewal.
	if err := hook(context.Background(), "cert_obtained", map[string]any{"identifier": cfg.ACME.Domains[0]}); err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 1 || notifications[0] != "DNSACMECertDeployed" {
		t.Fatalf("initial obtain must use the deployment notification, got %v", notifications)
	}
	if err := hook(context.Background(), "cert_obtained", map[string]any{"identifier": cfg.ACME.Domains[0], "renewal": true}); err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 2 || notifications[1] != "DNSACMECertRenewed" {
		t.Fatalf("renewal must use the renewal notification, got %v", notifications)
	}

	// A failed import must not announce success; the hook reports the error.
	server.Close()
	if err := hook(context.Background(), "cert_obtained", map[string]any{"identifier": cfg.ACME.Domains[0], "renewal": true}); err == nil {
		t.Fatal("expected import failure after the DSM endpoint went away")
	}
	if len(notifications) != 2 {
		t.Fatalf("failed import must not notify, got %v", notifications)
	}

	// A notification dispatch error stays non-fatal for the renewal itself.
	server2 := fakeSynologyServerWithCerts(t, map[string]string{"dnsacme": "cert-id-1"}, nil)
	u2, _ := url.Parse(server2.URL)
	host2, port2, _ := strings.Cut(u2.Host, ":")
	cfg.Synology.Host = host2
	cfg.Synology.Port = atoiForTest(port2)
	synologyNotifyCommand = func(ctx context.Context, tag string, vars map[string]string) error {
		notifications = append(notifications, tag)
		return errors.New("synonotify unavailable")
	}
	hook = synologyRenewalDeployHook(cfg, cfg.Runtime.StorageDir)
	if err := hook(context.Background(), "cert_obtained", map[string]any{"identifier": cfg.ACME.Domains[0], "renewal": true}); err != nil {
		t.Fatalf("notification failure must not fail the renewal hook: %v", err)
	}
	if len(notifications) != 3 || notifications[2] != "DNSACMECertRenewed" {
		t.Fatalf("expected the failing renewal notifier once, got %v", notifications)
	}
}

// retargetSynologyNotificationCache points the published-catalog directory at a
// temporary path so publish/present/remove exercise the real filesystem path
// without touching the host's root-owned /var/cache/texts. It also stubs the DSM
// category-db tools, which only exist on a real NAS, recording the languages
// registered so a test can assert every shipped language was covered.
func retargetSynologyNotificationCache(t *testing.T) (string, *[]string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "texts", "DNSACME")
	oldDir := synologyNotificationCacheDir
	oldReg := synologyRegisterNotificationCategory
	oldUnreg := synologyUnregisterNotificationCategory
	synologyNotificationCacheDir = dir
	registered := &[]string{}
	synologyRegisterNotificationCategory = func(lang string) error {
		*registered = append(*registered, lang)
		return nil
	}
	synologyUnregisterNotificationCategory = func() error { return nil }
	t.Cleanup(func() {
		synologyNotificationCacheDir = oldDir
		synologyRegisterNotificationCategory = oldReg
		synologyUnregisterNotificationCategory = oldUnreg
	})
	return dir, registered
}

func stubSynologyIsRoot(t *testing.T, root bool) {
	t.Helper()
	old := synologyIsRoot
	synologyIsRoot = func() bool { return root }
	t.Cleanup(func() { synologyIsRoot = old })
}

// Publishing writes the embedded catalog to disk and present/remove reflect it,
// so the send gate has a real published tree to observe.
func TestPublishSynologyNotificationTemplatesRoundTrip(t *testing.T) {
	dir, registered := retargetSynologyNotificationCache(t)
	if synologyNotificationTemplatesPresent() {
		t.Fatal("catalog should be absent before publishing")
	}
	if err := publishSynologyNotificationTemplates(); err != nil {
		t.Fatal(err)
	}
	if !synologyNotificationTemplatesPresent() {
		t.Fatal("catalog should be present after publishing")
	}
	// Presence alone is insufficient after an upgrade: a root-owned catalog from
	// an older package must be reported as stale so the UI asks for re-publishing.
	chsPath := filepath.Join(dir, "chs", "mails")
	originalCHS, err := os.ReadFile(chsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chsPath, append(originalCHS, []byte("\n# stale\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if synologyNotificationTemplatesPresent() {
		t.Fatal("catalog with stale content must require re-publishing")
	}
	if err := os.WriteFile(chsPath, originalCHS, 0o644); err != nil {
		t.Fatal(err)
	}
	if !synologyNotificationTemplatesPresent() {
		t.Fatal("catalog should be current again after restoring embedded content")
	}
	// Every shipped language must be registered into the category db, or synonotify
	// would silently drop that locale's events even though the text files exist.
	for _, lang := range []string{"enu", "chs"} {
		data, err := os.ReadFile(filepath.Join(dir, lang, "mails"))
		if err != nil {
			t.Fatalf("published %s catalog missing: %v", lang, err)
		}
		for _, marker := range []string{"[DNSACMECertRenewed]", "[DNSACMECertDeployed]"} {
			if !strings.Contains(string(data), marker) {
				t.Fatalf("published %s catalog missing %q", lang, marker)
			}
		}
		found := false
		for _, r := range *registered {
			if r == lang {
				found = true
			}
		}
		if !found {
			t.Fatalf("language %s was published but never registered in the category db, got %v", lang, *registered)
		}
	}
	if err := removeSynologyNotificationTemplates(); err != nil {
		t.Fatal(err)
	}
	if synologyNotificationTemplatesPresent() {
		t.Fatal("catalog should be absent after removal")
	}
}

// The daemon runs with umask 077 (inherited from start-stop-status), so the
// published catalog must be forced world-readable or DSM could not render events.
func TestPublishSynologyNotificationTemplatesIgnoresUmask(t *testing.T) {
	dir, _ := retargetSynologyNotificationCache(t)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if err := publishSynologyNotificationTemplates(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "enu"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("published dir must be 0755 despite umask, got %o", info.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(dir, "enu", "mails"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("published file must be 0644 despite umask, got %o", fi.Mode().Perm())
	}
}

func TestReconcileSynologyNotificationsKeepsEnabledWhenPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stubSynologyNotificationsPublished(t) // present() is true
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	reconcileSynologyNotifications(path)
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.NotificationsEnabled {
		t.Fatal("reconcile with a present catalog must keep notifications enabled")
	}
}

// The daemon never runs as root and cannot republish, so a missing catalog must
// not flip the user's persisted intent: the send gate already suppresses delivery
// and the log points at the one-time publish command until it is re-run.
func TestReconcileSynologyNotificationsKeepsIntentWhenCatalogMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t) // empty -> present() is false
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	reconcileSynologyNotifications(path)
	loaded, err := loadSynologyConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.NotificationsEnabled {
		t.Fatal("reconcile must not auto-disable notifications when the catalog is missing")
	}
}

// A config save must keep the file's existing owner, so a root-run write (the
// notifications action publishes and persists as root) does not lock the non-root
// package daemon out of its own config. The chownFile seam captures the target
// ownership without needing real root to change owners.
func TestSaveSynologyConfigPreservesExistingOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no unix stat available")
	}

	var gotUID, gotGID int
	chowned := false
	old := chownFile
	chownFile = func(name string, uid, gid int) error {
		chowned, gotUID, gotGID = true, uid, gid
		return nil
	}
	defer func() { chownFile = old }()

	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if !chowned {
		t.Fatal("save over an existing config must chown the new file to preserve ownership")
	}
	if gotUID != int(st.Uid) || gotGID != int(st.Gid) {
		t.Fatalf("save chowned to %d:%d, want the existing owner %d:%d", gotUID, gotGID, st.Uid, st.Gid)
	}
}

// A first-time config save (no existing file) must chown the new file to its
// containing directory's owner. The one-time publish command runs as root and can
// create config before the wizard ever saves it; without inheriting the
// package-owned etc directory, that root-written config would lock the non-root
// daemon out just like the earlier ownership bug.
func TestSaveSynologyConfigInheritsDirOwnerWhenFileAbsent(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "etc")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "config.yaml")
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no unix stat available")
	}

	var gotUID, gotGID int
	chowned := false
	old := chownFile
	chownFile = func(name string, uid, gid int) error {
		chowned, gotUID, gotGID = true, uid, gid
		return nil
	}
	defer func() { chownFile = old }()

	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	if !chowned {
		t.Fatal("first save must chown the new file to inherit the directory owner")
	}
	if gotUID != int(st.Uid) || gotGID != int(st.Gid) {
		t.Fatalf("first save chowned to %d:%d, want the directory owner %d:%d", gotUID, gotGID, st.Uid, st.Gid)
	}
}

// The ordinary config GET the UI loads on open must carry notificationsPublished so
// applyConfig can warn when notifications are enabled but the catalog is gone,
// instead of showing a checkbox that is silently undeliverable.
func TestCGIConfigResponseIncludesNotificationsPublished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stubSynologyNotificationsPublished(t) // present() is true
	cfg := validSynologyConfig(dir)
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiConfig(http.MethodGet, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["notificationsPublished"] != true {
		t.Fatalf("config response must include notificationsPublished, got %v", resp["notificationsPublished"])
	}
}

// NotificationsEnabled must not touch the identity hash (so a toggle never
// invalidates test/apply state) but must change the reload key, so the daemon
// reloads and its renewal deploy hook stops using a stale captured value.
func TestNotificationsEnabledStaysOutOfHashButReloadsDaemon(t *testing.T) {
	dir := t.TempDir()
	on := validSynologyConfig(dir)
	on.NotificationsEnabled = true
	off := on
	off.NotificationsEnabled = false
	if on.ConfigHash() != off.ConfigHash() {
		t.Fatal("NotificationsEnabled must not affect the config hash")
	}
	if renewalReloadKey(on) == renewalReloadKey(off) {
		t.Fatal("toggling NotificationsEnabled must change the renewal reload key")
	}
}

func TestNotificationCatalogRegistrationStaysOutOfHashButReloadsDaemon(t *testing.T) {
	dir := t.TempDir()
	registered := validSynologyConfig(dir)
	registered.NotificationsEnabled = true
	registered.NotificationCatalogRegistered = true
	unregistered := registered
	unregistered.NotificationCatalogRegistered = false
	if registered.ConfigHash() != unregistered.ConfigHash() {
		t.Fatal("notification registration must not affect the certificate config hash")
	}
	if renewalReloadKey(registered) == renewalReloadKey(unregistered) {
		t.Fatal("publishing the notification catalog must reload the daemon")
	}
}

// A running daemon must reload when notifications are toggled, otherwise the
// already-built renewal deploy hook keeps the stale intent.
func TestMonitorSynologyConfigChangeDetectsNotificationToggle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	hash := cfg.ConfigHash()
	cfg.LastTest = SynologyOperationState{Success: true, ConfigHash: hash}
	cfg.LastApply = SynologyOperationState{Success: true, ConfigHash: hash}
	cfg.NotificationsEnabled = false
	activeKey := renewalReloadKey(cfg)

	cfg.NotificationsEnabled = true
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	old := synologyDaemonRetryInterval
	synologyDaemonRetryInterval = time.Millisecond
	defer func() { synologyDaemonRetryInterval = old }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !monitorSynologyConfigChange(ctx, path, activeKey) {
		t.Fatal("enabling notifications on a running daemon must trigger a reload")
	}
}

// Enabling before the one-time publish command has run (no catalog on disk) must
// not persist an undeliverable enabled state; it asks the UI to show the publish
// command instead. The CGI never runs as root and never publishes itself.
func TestCGINotificationsEnableWithoutCatalogNeedsPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t) // empty -> present() is false
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiNotifications(path, strings.NewReader(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["needsPublish"] != true || resp["enabled"] != false {
		t.Fatalf("enable without a catalog must return needsPublish without enabling, got %v", resp)
	}
	loaded, _ := loadSynologyConfig(path)
	if loaded.NotificationsEnabled {
		t.Fatal("enable without a catalog must not persist enabled")
	}
}

// DSM preserves the global notification catalog across package uninstall, but a
// fresh package config has no proof that notification_utils re-registered it and
// emitted the browser string-refresh event. Matching bytes alone must therefore
// still request publish once after a reinstall.
func TestCGINotificationsFreshInstallWithPreservedCatalogNeedsPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stubSynologyNotificationsPublished(t) // preserved files exactly match
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiNotifications(path, strings.NewReader(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["needsPublish"] != true || resp["enabled"] != false {
		t.Fatalf("fresh install with a preserved catalog must re-publish, got %v", resp)
	}
}

// Once the catalog is published, enabling is a plain non-root config flip.
func TestCGINotificationsEnableWithCatalogPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stubSynologyNotificationsPublished(t) // present() is true
	cfg := validSynologyConfig(dir)
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiNotifications(path, strings.NewReader(`{"enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["enabled"] != true {
		t.Fatalf("enable with a catalog must report enabled, got %v", resp)
	}
	loaded, _ := loadSynologyConfig(path)
	if !loaded.NotificationsEnabled {
		t.Fatal("enable with a catalog must persist enabled")
	}
}

// Disabling is a config flip; the persistent catalog is left in place so a later
// re-enable needs no root.
func TestCGINotificationsDisablePersistsAndKeepsCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t)
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := publishSynologyNotificationTemplates(); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiNotifications(path, strings.NewReader(`{"enabled":false}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["enabled"] != false {
		t.Fatalf("disable must report disabled, got %v", resp)
	}
	loaded, _ := loadSynologyConfig(path)
	if loaded.NotificationsEnabled {
		t.Fatal("disable must persist disabled")
	}
	if !synologyNotificationTemplatesPresent() {
		t.Fatal("disable must keep the published catalog for a cheap re-enable")
	}
}

// The one-time root command publishes the catalog, registers events, and enables
// notifications so the non-root daemon can deliver them afterwards.
func TestRunSynologyPublishNotificationsPublishesAndEnables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t)
	stubSynologyIsRoot(t, true)
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	if err := runSynologyPublishNotifications(path, false); err != nil {
		t.Fatal(err)
	}
	if !synologyNotificationTemplatesPresent() {
		t.Fatal("publish must write the catalog")
	}
	loaded, _ := loadSynologyConfig(path)
	if !loaded.NotificationsEnabled {
		t.Fatal("publish must enable notifications")
	}
	if !loaded.NotificationCatalogRegistered {
		t.Fatal("publish must mark the catalog registered for this installation")
	}
}

// --disable removes the catalog and clears the toggle.
func TestRunSynologyPublishNotificationsDisableRemovesAndClears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t)
	stubSynologyIsRoot(t, true)
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err := publishSynologyNotificationTemplates(); err != nil {
		t.Fatal(err)
	}
	if err := runSynologyPublishNotifications(path, true); err != nil {
		t.Fatal(err)
	}
	if synologyNotificationTemplatesPresent() {
		t.Fatal("--disable must remove the catalog")
	}
	loaded, _ := loadSynologyConfig(path)
	if loaded.NotificationsEnabled {
		t.Fatal("--disable must clear the toggle")
	}
	if loaded.NotificationCatalogRegistered {
		t.Fatal("--disable must clear the catalog registration marker")
	}
}

// Publishing must refuse to run as a non-root user rather than silently fail to
// write the root-owned catalog.
func TestRunSynologyPublishNotificationsRefusesNonRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	retargetSynologyNotificationCache(t)
	stubSynologyIsRoot(t, false)
	if err := saveSynologyConfig(path, validSynologyConfig(dir)); err != nil {
		t.Fatal(err)
	}
	if err := runSynologyPublishNotifications(path, false); err == nil {
		t.Fatal("publish must refuse to run as non-root")
	}
	if synologyNotificationTemplatesPresent() {
		t.Fatal("a refused publish must not write the catalog")
	}
	loaded, _ := loadSynologyConfig(path)
	if loaded.NotificationsEnabled {
		t.Fatal("a refused publish must not enable notifications")
	}
}

// The status action surfaces both the persisted toggle and whether the catalog is
// live, so the UI can distinguish "enabled and deliverable" from "enabled but the
// catalog is gone".
func TestCGIStatusReportsNotificationState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	stubSynologyNotificationsPublished(t) // present() is true
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	markSynologyNotificationCatalogRegistered(&cfg)
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	payload, err := cgiStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := payload.(map[string]any)
	if resp["notificationsEnabled"] != true {
		t.Fatalf("status must report notificationsEnabled, got %v", resp["notificationsEnabled"])
	}
	if resp["notificationsPublished"] != true {
		t.Fatalf("status must report notificationsPublished, got %v", resp["notificationsPublished"])
	}
	if _, exists := resp["testPassed"]; !exists {
		t.Fatal("status must expose the optional staging test state")
	}
	statusConfig, ok := resp["config"].(SynologyConfig)
	if !ok {
		t.Fatalf("status must return a config for apply reconciliation, got %T", resp["config"])
	}
	if statusConfig.Synology.Password != "********" {
		t.Fatal("status reconciliation config must redact the DSM password")
	}
	if _, exists := resp["canApply"]; exists {
		t.Fatal("status must not expose the removed staging apply gate")
	}
}

// A normal configuration form save never carries the notifications toggle, so it
// must preserve whatever the dedicated action last persisted.
func TestCGIConfigPreservesNotificationsEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := validSynologyConfig(dir)
	cfg.NotificationsEnabled = true
	if err := saveSynologyConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	body := `{"acme":{"domains":["example.com"],"email":"a@example.com","keyType":"rsa4096","ca":"letsencrypt"},` +
		`"dns":{"provider":"cloudflare","config":{}},` +
		`"synology":{"scheme":"https","host":"127.0.0.1","port":5001,"account":"admin","password":"pw","certificateDesc":"dnsacme","create":true,"asDefault":true}}`
	if _, err := cgiConfig(http.MethodPost, path, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	loaded, _ := loadSynologyConfig(path)
	if !loaded.NotificationsEnabled {
		t.Fatal("a normal config save must preserve notificationsEnabled")
	}
}

// The default dispatcher must fail fast on a dead context instead of blocking a
// renewal event handler on an unresponsive synonotify.
func TestSynologyNotifyCommandFailsFastOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := synologyNotifyCommand(ctx, "DNSACMECertRenewed", map[string]string{"%CERT_DOMAIN%": "example.com"}); err == nil {
		t.Fatal("expected an error from a cancelled context or missing synonotify binary")
	}
}
