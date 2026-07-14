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

func TestSynologyLifecycleDropsRootBeforeStart(t *testing.T) {
	data, err := os.ReadFile("synology/spk/scripts/start-stop-status")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if !strings.Contains(script, `if [ "$(id -u)" -eq 0 ]; then`) {
		t.Fatal("lifecycle script must detect a direct root start")
	}
	if !strings.Contains(script, `exec su -s /bin/sh dnsacme -c "/var/packages/dnsacme/scripts/start-stop-status start"`) {
		t.Fatal("lifecycle script must drop root before launching the daemon")
	}
}

func TestSynologyUninstallRemovesPersistentDataOnlyOnUninstall(t *testing.T) {
	data, err := os.ReadFile("synology/spk/scripts/postuninst")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if !strings.Contains(script, `if [ "$SYNOPKG_PKG_STATUS" = "UNINSTALL" ]; then`) {
		t.Fatal("postuninst must restrict destructive cleanup to a real uninstall")
	}
	for _, path := range []string{
		"/var/packages/dnsacme/var",
		"/var/packages/dnsacme/etc",
		"/var/packages/dnsacme/home",
	} {
		if !strings.Contains(script, path) {
			t.Fatalf("postuninst does not clean %s", path)
		}
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

func TestSynologyUIHasNoRemovedAdvancedOptions(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, removed := range []string{
		`option.notifications`,
		`publish-notifications`,
		`onNotificationToggle`,
		`notificationsPublished`,
		`renewalWindowRatio`,
		`fRenewRatio`,
	} {
		if strings.Contains(source, removed) {
			t.Fatalf("removed notification UI marker is still present: %s", removed)
		}
	}
}

func TestSynologyUIClampsInitialSizeAndReflowsNestedCards(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	for _, marker := range []string{
		"me.fitInitialWindowSize(windowConfig);",
		"config.width = Math.max(minWidth, Math.min(requestedWidth, maxWidth));",
		"config.height = Math.max(minHeight, Math.min(requestedHeight, maxHeight));",
		`this.on("resize", function () { me.reflowWindowLayout.defer(1, me); }, this);`,
		"if (active && active.doLayout) { active.doLayout(); }",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("responsive window sizing is missing %q", marker)
		}
	}
	// The outer window, each card root, and each centered inner card must all
	// participate in layout. Form roots anchor width instead of fitting height so
	// autoScroll can measure expanded advanced fields; the log root keeps fit.
	if strings.Count(source, `layout: "fit"`) < 2 {
		t.Fatal("window and log card roots no longer use fit layout")
	}
	if strings.Count(source, `layout: "anchor"`) < 3 {
		t.Fatal("centered cards no longer resize their children")
	}
}

func TestSynologyUIFormScrollMeasuresNaturalContentHeight(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	start := strings.Index(source, "    var form = new Ext.form.FormPanel({")
	end := strings.Index(source[start:], "\n    form.dnsacmeInner")
	if start < 0 || end < 0 {
		t.Fatal("formPanel root block not found")
	}
	block := source[start : start+end]
	for _, marker := range []string{
		`layout: "anchor"`,
		`defaults: { anchor: "100%" }`,
		`autoScroll: true`,
	} {
		if !strings.Contains(block, marker) {
			t.Fatalf("scrollable form root is missing %q", marker)
		}
	}
	if strings.Contains(block, `layout: "fit"`) {
		t.Fatal("fit height prevents the form root from measuring overflow")
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
	if !strings.Contains(source, "this.setActionsBusy(false);") {
		t.Fatal("reconfiguration does not restore the independent Test and Apply actions")
	}
}

func TestSynologyUIOffersOptionalTestAndDirectProductionApply(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)

	for _, marker := range []string{
		`me.requestAction("test-run")`,
		`me.requestAction("apply")`,
		`dialog.applyUntestedBody`,
		`dialog.applyRecentTestBody`,
		`dialog.testSuccessBody`,
		`10 * 60 * 1000`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("optional test/apply flow is missing %q", marker)
		}
	}
	for _, removed := range []string{"fForceStaging", "option.forceStaging", "hint.needTest", "updateApplyGate"} {
		if strings.Contains(source, removed) {
			t.Fatalf("removed staging gate remains in the UI: %s", removed)
		}
	}
}

func TestSynologyUIApplySuccessUsesReturnedConfigWithoutReload(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	start := strings.Index(source, "  finishAction: function (action, data) {")
	end := strings.Index(source[start:], "\n\n  reconcileActionState:")
	if start < 0 || end < 0 {
		t.Fatal("finishAction block not found")
	}
	block := source[start : start+end]
	for _, marker := range []string{
		"me.setActionsBusy(false);",
		"me.cfg = data.config;",
		"me.enterDeployedView(data.config);",
		"me.loadLogs();",
	} {
		if !strings.Contains(block, marker) {
			t.Fatalf("apply success settlement is missing %q", marker)
		}
	}
	if strings.Contains(block, "me.loadAll()") {
		t.Fatal("apply success still issues a config reload after the long CGI request")
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

func TestSynologyUILogRefreshTargetsVisibleArea(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, marker := range []string{
		"visibleLogArea: function ()",
		`me.setLogArea(me.visibleLogArea(), data.logs || "")`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("visible log refresh is missing %q", marker)
		}
	}
	for _, hiddenRefresh := range []string{
		"me.setLogArea(me.logsArea,",
		"me.setLogArea(me.deployedLogsArea,",
	} {
		if strings.Contains(source, hiddenRefresh) {
			t.Fatalf("log polling still refreshes a hidden area: %s", hiddenRefresh)
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
