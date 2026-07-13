package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// synologyNotificationTemplateFS carries the localized DSM notification catalog so
// publishing never depends on the extracted package directory or a lifecycle
// script (both of which run sandboxed for /var/cache on this DSM). The build
// embeds it from the repository at compile time.
//
//go:embed synology/spk/notification
var synologyNotificationTemplateFS embed.FS

const synologyNotificationEmbedRoot = "synology/spk/notification"

// synologyNotificationPkgName is the notification source key DSM indexes this
// package's events under (the /var/cache/texts subdirectory and the source column
// in notification_category.db).
const synologyNotificationPkgName = "DNSACME"

// synologyNotificationUtils compiles a package's published text catalog into DSM's
// notification_category.db. synonotify only delivers tags registered there, so
// publishing the raw text files is necessary but not sufficient: an unregistered
// tag is silently dropped. This is the tool a signed package's sysnotify resource
// runs internally; we invoke it directly since that resource is signed-only.
var synologyNotificationUtils = "/usr/syno/bin/notification_utils"

// synologyRegisterNotificationCategory registers one language's published catalog
// into notification_category.db. It is a var so tests can stub the DSM tool. The
// tool must run after the text files are published because it reads them from the
// package's /var/cache/texts subdirectory.
var synologyRegisterNotificationCategory = func(lang string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, synologyNotificationUtils, "--gen_category_db_file", synologyNotificationPkgName, lang).Run()
}

// synologyUnregisterNotificationCategory removes this package's tags from
// notification_category.db when notifications are turned off. A var for tests.
var synologyUnregisterNotificationCategory = func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, synologyNotificationUtils, "--remove_category_db_file", synologyNotificationPkgName).Run()
}

// synologyNotificationCacheDir is where DSM's synonotify reads a package's text
// catalog. It is a var so tests can retarget it to a temporary directory. The
// directory is root-owned, so publishing requires the package to run as root.
var synologyNotificationCacheDir = "/var/cache/texts/DNSACME"

// synologyIsRoot reports whether this process can write the root-owned catalog
// directory. The daemon and CGI always run as the package user; only the one-time
// publish-notifications command is expected to run as root (via sudo), so this
// guards that command. A var for tests.
var synologyIsRoot = func() bool { return os.Geteuid() == 0 }

// synologyPublishCommand is the exact command a user runs once, as root, to make
// DSM notifications deliverable. The CGI-driven UI dialog and the daemon's log
// guidance both name this same command so the instruction never drifts.
const synologyPublishCommand = "sudo /var/packages/dnsacme/target/bin/dnsacme synology publish-notifications"

// runSynologyPublishNotifications is the one-time, root-only command that makes
// DSM notifications deliverable. Publishing writes the root-owned text catalog and
// registers the tags in notification_category.db; both need root, but only once,
// because /var/cache/texts is persistent. The daemon and CGI never run as root, so
// this transient sudo command is the only place the package touches root. With
// disable it tears the catalog down and clears the toggle. Config is saved with
// preserveFileOwnership so a root-invoked write keeps the package user's ownership.
func runSynologyPublishNotifications(configPath string, disable bool) error {
	if !synologyIsRoot() {
		return fmt.Errorf("this command must run as root: %s", synologyPublishCommand)
	}
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return err
	}
	cfg = normalizeSynologyConfig(cfg)
	if disable {
		if err := removeSynologyNotificationTemplates(); err != nil {
			return err
		}
		cfg.NotificationsEnabled = false
		if err := saveSynologyConfig(configPath, cfg); err != nil {
			return err
		}
		fmt.Println("Notification templates removed; system notifications disabled.")
		return nil
	}
	if err := publishSynologyNotificationTemplates(); err != nil {
		return err
	}
	if !synologyNotificationTemplatesPresent() {
		return fmt.Errorf("published notification templates are not visible under %s", synologyNotificationCacheDir)
	}
	cfg.NotificationsEnabled = true
	if err := saveSynologyConfig(configPath, cfg); err != nil {
		return err
	}
	fmt.Println("Notification templates published; system notifications enabled.")
	return nil
}

// synologyNotificationTemplatesPresent reports whether every published catalog
// file exists and exactly matches the templates embedded in this binary. A
// package reinstall or upgrade can leave an older root-owned catalog behind; in
// that case the UI must ask the user to re-run publish-notifications instead of
// treating the stale files as ready. A var so tests can simulate catalog state.
var synologyNotificationTemplatesPresent = func() bool {
	err := fs.WalkDir(synologyNotificationTemplateFS, synologyNotificationEmbedRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, synologyNotificationEmbedRoot), "/")
		want, err := synologyNotificationTemplateFS.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(synologyNotificationCacheDir, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("published notification template differs: %s", rel)
		}
		return nil
	})
	return err == nil
}

// publishSynologyNotificationTemplates writes the embedded catalog into
// synologyNotificationCacheDir and registers its tags in notification_category.db.
// It requires root because that directory is root-owned; the only caller is the
// root-gated runSynologyPublishNotifications command. Both steps are required:
// synonotify reads the text files for the message body but only delivers tags
// registered in the category db, so a published-but-unregistered tag is silently
// dropped. Publishing is idempotent: a refresh overwrites stale files and
// re-registers, so re-running the publish command picks up new events after a
// package upgrade ships additional templates.
func publishSynologyNotificationTemplates() error {
	if err := writeSynologyNotificationFiles(); err != nil {
		return err
	}
	// Register each shipped language separately: notification_utils compiles one
	// language's catalog per call, and the tool must run after the files exist
	// because it reads them from the package's /var/cache/texts subdirectory.
	langs, err := synologyNotificationLanguages()
	if err != nil {
		return err
	}
	for _, lang := range langs {
		if err := synologyRegisterNotificationCategory(lang); err != nil {
			return err
		}
	}
	return nil
}

// writeSynologyNotificationFiles copies the embedded catalog to disk with
// world-readable modes.
func writeSynologyNotificationFiles() error {
	return fs.WalkDir(synologyNotificationTemplateFS, synologyNotificationEmbedRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(path, synologyNotificationEmbedRoot), "/")
		dst := synologyNotificationCacheDir
		if rel != "" {
			dst = filepath.Join(synologyNotificationCacheDir, filepath.FromSlash(rel))
		}
		if d.IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			// Chmod after MkdirAll so the mode is not narrowed by the process umask.
			// The daemon inherits umask 077 from start-stop-status, which would
			// otherwise publish a 0700 catalog that only a root reader could use; DSM
			// notification catalogs are world-readable (0755) by convention.
			return os.Chmod(dst, 0o755)
		}
		data, err := synologyNotificationTemplateFS.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return err
		}
		// os.WriteFile also applies the umask, so set the final mode explicitly.
		return os.Chmod(dst, 0o644)
	})
}

// synologyNotificationLanguages lists the language codes shipped in the embedded
// catalog (its top-level directory names), so registration follows whatever
// languages the package actually ships without a separate hardcoded list.
func synologyNotificationLanguages() ([]string, error) {
	entries, err := synologyNotificationTemplateFS.ReadDir(synologyNotificationEmbedRoot)
	if err != nil {
		return nil, err
	}
	langs := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			langs = append(langs, e.Name())
		}
	}
	return langs, nil
}

// removeSynologyNotificationTemplates unpublishes the catalog and unregisters its
// tags when the user turns notifications off. Best effort: a non-root process
// cannot remove the root-owned tree, but the send gate already stops delivery once
// the toggle is off. Unregistering keeps notification_category.db tidy.
func removeSynologyNotificationTemplates() error {
	_ = synologyUnregisterNotificationCategory()
	return os.RemoveAll(synologyNotificationCacheDir)
}

// synologyNotificationsDeliverable is the send gate for both notification events.
// The persisted toggle is the user's intent and the live catalog check is the
// authority, so a disabled toggle or a missing catalog both suppress delivery.
func synologyNotificationsDeliverable(cfg SynologyConfig) bool {
	return cfg.NotificationsEnabled && synologyNotificationTemplatesPresent()
}

// reconcileSynologyNotifications checks the published catalog against the persisted
// toggle once on daemon startup. The daemon always runs as the package user and so
// cannot publish (that needs root) or safely flip the user's intent, so it only
// logs guidance: if notifications are enabled but the catalog is gone (DSM can drop
// it when it rebuilds notification_category.db), it points at the one-time publish
// command. The persisted toggle is left untouched, and the send gate
// (synologyNotificationsDeliverable) already suppresses delivery while the catalog
// is absent, so a re-publish resumes notifications without re-toggling.
func reconcileSynologyNotifications(configPath string) {
	cfg, err := loadSynologyConfig(configPath)
	if err != nil {
		return
	}
	cfg = normalizeSynologyConfig(cfg)
	if !cfg.NotificationsEnabled {
		return
	}
	if synologyNotificationTemplatesPresent() {
		return
	}
	appendSynologyLog(cfg, "notifications are enabled but the DSM text catalog is missing (DSM may have rebuilt its notification database); re-publish with: "+synologyPublishCommand)
}
