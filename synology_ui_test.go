package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestSynologyUII18NCatalogCoverage(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	start := strings.Index(source, "// I18N_CATALOG_START")
	end := strings.Index(source, "// I18N_CATALOG_END")
	if start < 0 || end <= start {
		t.Fatal("DNSACME.js is missing the i18n catalog boundary")
	}
	catalog := source[start:end]
	en := catalogKeys(t, catalog, "  en: {", "  },\n  \"zh-CN\": {")
	zh := catalogKeys(t, catalog, "  \"zh-CN\": {", "\n  }\n};")

	for key := range en {
		if !zh[key] {
			t.Errorf("zh-CN catalog is missing %q", key)
		}
	}
	for key := range zh {
		if !en[key] {
			t.Errorf("English catalog is missing %q", key)
		}
	}

	usageRE := regexp.MustCompile(`DNSACME\.t\("([^"]+)"`)
	for _, match := range usageRE.FindAllStringSubmatch(source[end:], -1) {
		if !en[match[1]] || !zh[match[1]] {
			t.Errorf("translation key %q is not present in both catalogs", match[1])
		}
	}

	// Chinese UI copy must remain inside the catalog so locale switching cannot
	// leave a newly added label or error message permanently untranslated.
	outsideCatalog := source[:start] + source[end+len("// I18N_CATALOG_END"):]
	if match := regexp.MustCompile(`\p{Han}`).FindString(outsideCatalog); match != "" {
		t.Fatalf("found hard-coded Chinese text outside the i18n catalog: %q", match)
	}
	if !strings.Contains(source, `_T("common", "cancel")`) {
		t.Fatal("locale resolver no longer follows the active DSM translation session")
	}
}

func TestSynologyPackageMaintainerLinksToRepository(t *testing.T) {
	data, err := os.ReadFile("synology/spk/INFO")
	if err != nil {
		t.Fatal(err)
	}
	info := string(data)
	if !strings.Contains(info, `maintainer="mritd"`) {
		t.Fatal("SPK maintainer is missing")
	}
	if !strings.Contains(info, `maintainer_url="https://github.com/mritd/dnsacme"`) {
		t.Fatal("SPK maintainer URL must link to the dnsacme repository")
	}
}

func TestSynologyUIButtonTextUsesDSMNativeMetrics(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	// DSM 7.2 renders SYNO.ux.Button at 24px. A taller text line box shifts the
	// label baseline downward even when its toolbar cell is vertically centered.
	want := ".dnsacme-win .syno-ux-button .x-btn-text { height:24px !important; padding:0 18px !important; font-size:13px !important; line-height:24px !important; }"
	if !strings.Contains(source, want) {
		t.Fatal("button text no longer matches DSM's native 24px vertical metrics")
	}
}

func TestSynologyUIReconfigurationStateIsServerBacked(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	if !strings.Contains(source, `DNSACME.request("reconfigure", "POST"`) {
		t.Fatal("reconfigure action is not persisted through the CGI")
	}
	if !strings.Contains(source, "me.forceWizard = !!cfg.reconfiguring;") {
		t.Fatal("startup does not restore persisted reconfiguration mode")
	}
	if !strings.Contains(source, "reloadData.config.reconfiguring") {
		t.Fatal("HTTP 0 reconfiguration does not reconcile persisted server state")
	}
	if !strings.Contains(source, "this.applyBtn.setDisabled(true);") {
		t.Fatal("reconfiguration does not immediately disable production apply")
	}
}

func TestSynologyUIFailureDialogUsesLocalizedMessages(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	for _, marker := range []string{"dnsacme-error-icon", "dnsacme-error-title", "dnsacme-error-message"} {
		if !strings.Contains(source, marker) {
			t.Fatalf("failure dialog is missing %s", marker)
		}
	}
	for _, key := range []string{"error.dsmLogin", "error.dnsValidation", "error.dnsProvider", "error.caRateLimited", "error.dsmImport"} {
		if !strings.Contains(source, `DNSACME.t("`+key+`")`) {
			t.Fatalf("failure dialog does not map %s", key)
		}
	}
	if strings.Contains(source, `htmlEncode(reason || SYNO.SDS.DNSACME.t("error.requestFailed"))`) {
		t.Fatal("failure dialog still renders raw log text")
	}
}

func TestSynologyUILogLevelsAreColoredAfterEscaping(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	for _, marker := range []string{"dnsacme-log-error", "dnsacme-log-warn", "Ext.util.Format.htmlEncode(line)"} {
		if !strings.Contains(source, marker) {
			t.Fatalf("colored log rendering is missing %s", marker)
		}
	}
}

func catalogKeys(t *testing.T, source, startMarker, endMarker string) map[string]bool {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("catalog marker %q was not found", startMarker)
	}
	block := source[start+len(startMarker):]
	end := strings.Index(block, endMarker)
	if end < 0 {
		t.Fatalf("catalog marker %q was not found", endMarker)
	}

	keys := make(map[string]bool)
	keyRE := regexp.MustCompile(`(?m)^\s*"([^"]+)":`)
	for _, match := range keyRE.FindAllStringSubmatch(block[:end], -1) {
		keys[match[1]] = true
	}
	return keys
}
