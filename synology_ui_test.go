//go:build synology

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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

func TestSynologyUICertificateDescriptionDefault(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `emptyText: "DNSACME"`) {
		t.Fatal("certificate description placeholder must match the package default")
	}
}

func TestSynologyApplicationIdentifierIsConsistent(t *testing.T) {
	const (
		applicationID    = "com.synocommunity.packages.dnsacme"
		oldApplicationID = "SYNO.SDS.DNSACME.Application"
	)

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "INFO dsmappname",
			path: "synology/spk/INFO",
			want: `dsmappname="` + applicationID + `"`,
		},
		{
			name: "UI config application key",
			path: "synology/spk/ui/config",
			want: `"` + applicationID + `": {`,
		},
		{
			name: "AppInstance class",
			path: "synology/spk/ui/DNSACME.js",
			want: `Ext.define("` + applicationID + `", {`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			source := string(data)
			if !strings.Contains(source, tt.want) {
				t.Fatalf("%s is missing application identifier %q", tt.path, applicationID)
			}
			if strings.Contains(source, oldApplicationID) {
				t.Fatalf("%s still contains obsolete application identifier %q", tt.path, oldApplicationID)
			}
		})
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
	if !strings.Contains(script, `exec su -s /bin/sh sc-dnsacme -c "/var/packages/dnsacme/scripts/start-stop-status start"`) {
		t.Fatal("lifecycle script must drop root before launching the daemon")
	}
}

func TestSynologyPackageIdentityAndRootMigrationHooks(t *testing.T) {
	data, err := os.ReadFile("synology/spk/conf/privilege")
	if err != nil {
		t.Fatal(err)
	}
	var privilege struct {
		Defaults struct {
			RunAs string `json:"run-as"`
		} `json:"defaults"`
		Username   string `json:"username"`
		Groupname  string `json:"groupname"`
		CtrlScript []struct {
			Action string `json:"action"`
			RunAs  string `json:"run-as"`
		} `json:"ctrl-script"`
	}
	if err := json.Unmarshal(data, &privilege); err != nil {
		t.Fatalf("invalid privilege manifest: %v", err)
	}
	if privilege.Defaults.RunAs != "package" {
		t.Fatalf("default lifecycle identity = %q, want package", privilege.Defaults.RunAs)
	}
	if privilege.Username != "sc-dnsacme" {
		t.Fatalf("package username = %q, want sc-dnsacme", privilege.Username)
	}
	if privilege.Groupname != "synocommunity" {
		t.Fatalf("package group = %q, want synocommunity", privilege.Groupname)
	}
	wantRoot := map[string]bool{"postinst": false, "postupgrade": false}
	for _, override := range privilege.CtrlScript {
		if _, ok := wantRoot[override.Action]; !ok {
			t.Errorf("unexpected lifecycle identity override for %s", override.Action)
			continue
		}
		if override.RunAs != "root" {
			t.Errorf("%s lifecycle identity = %q, want root", override.Action, override.RunAs)
			continue
		}
		wantRoot[override.Action] = true
	}
	for action, found := range wantRoot {
		if !found {
			t.Errorf("privilege manifest does not run %s as root", action)
		}
	}
}

func TestSynologyOwnershipMigrationIsGuarded(t *testing.T) {
	data, err := os.ReadFile("synology/spk/scripts/repair-ownership")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, marker := range []string{
		`if [ "$(id -u)" -ne 0 ]; then`,
		`id "$PACKAGE_USER"`,
		`id -gn "$PACKAGE_USER"`,
		`readlink -f "$logical_root"`,
		`if [ -L "$logical_root" ]; then`,
		`""|/)`,
		`@appdata:/usr/local/packages/@appdata/${PACKAGE_NAME}`,
		`@appconf:/usr/syno/etc/packages/${PACKAGE_NAME}`,
		`@apphome:/usr/local/packages/@apphome/${PACKAGE_NAME}`,
		`/volume${volume_name}/${storage_name}/${PACKAGE_NAME}`,
		`chown -hR -P "${PACKAGE_USER}:${PACKAGE_GROUP}" "$resolved_root"`,
		`repair_package_root "${PACKAGE_ROOT}/var" "@appdata"`,
		`repair_package_root "${PACKAGE_ROOT}/etc" "@appconf"`,
		`repair_package_root "${PACKAGE_ROOT}/home" "@apphome"`,
	} {
		if !strings.Contains(script, marker) {
			t.Errorf("ownership migration is missing %q", marker)
		}
	}
}

func TestSynologyOwnershipMigrationValidatesExactDSMRoots(t *testing.T) {
	helper := "synology/spk/scripts/repair-ownership"
	tests := []struct {
		name    string
		root    string
		storage string
		valid   bool
	}{
		{name: "system appdata", root: "/usr/local/packages/@appdata/dnsacme", storage: "@appdata", valid: true},
		{name: "system appconf", root: "/usr/syno/etc/packages/dnsacme", storage: "@appconf", valid: true},
		{name: "system apphome", root: "/usr/local/packages/@apphome/dnsacme", storage: "@apphome", valid: true},
		{name: "volume appdata", root: "/volume1/@appdata/dnsacme", storage: "@appdata", valid: true},
		{name: "volume appconf", root: "/volume12/@appconf/dnsacme", storage: "@appconf", valid: true},
		{name: "volume apphome", root: "/volume2/@apphome/dnsacme", storage: "@apphome", valid: true},
		{name: "empty", root: "", storage: "@appdata", valid: false},
		{name: "filesystem root", root: "/", storage: "@appdata", valid: false},
		{name: "wrong package", root: "/usr/local/packages/@appdata/other", storage: "@appdata", valid: false},
		{name: "wrong storage class", root: "/usr/local/packages/@appdata/dnsacme", storage: "@apphome", valid: false},
		{name: "child path", root: "/volume1/@appdata/dnsacme/child", storage: "@appdata", valid: false},
		{name: "non-numeric volume", root: "/volumeUSB1/@appdata/dnsacme", storage: "@appdata", valid: false},
		{name: "numeric prefix only", root: "/volume1evil/@appdata/dnsacme", storage: "@appdata", valid: false},
		{name: "lookalike tree", root: "/tmp/@appdata/dnsacme", storage: "@appdata", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", `. "$1"; validate_package_root "$2" "$3"`, "sh", helper, tt.root, tt.storage)
			err := cmd.Run()
			if tt.valid && err != nil {
				t.Fatalf("valid DSM root rejected: %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatal("unsafe DSM root accepted")
			}
		})
	}
}

func TestSynologyOwnershipMigrationRejectsDanglingRootSymlink(t *testing.T) {
	tempDir := t.TempDir()
	packageRoot := filepath.Join(tempDir, "package")
	if err := os.Mkdir(packageRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	logicalRoot := filepath.Join(packageRoot, "var")
	if err := os.Symlink(filepath.Join(tempDir, "missing-appdata"), logicalRoot); err != nil {
		t.Fatal(err)
	}

	helper, err := filepath.Abs("synology/spk/scripts/repair-ownership")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", `. "$1"; PACKAGE_ROOT=$2; repair_package_root "${PACKAGE_ROOT}/var" "@appdata"`, "sh", helper, packageRoot)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("dangling package root symlink was accepted")
	}
	if !strings.Contains(string(output), "package root is a dangling symlink") {
		t.Fatalf("unexpected dangling symlink error: %s", output)
	}
}

func TestSynologyOwnershipMigrationResolvesRootAndUsesPhysicalChown(t *testing.T) {
	tempDir := t.TempDir()
	packageRoot := filepath.Join(tempDir, "package")
	physicalRoot := filepath.Join(tempDir, "physical-appdata")
	mockBin := filepath.Join(tempDir, "bin")
	for _, path := range []string{packageRoot, physicalRoot, mockBin} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(physicalRoot, filepath.Join(packageRoot, "var")); err != nil {
		t.Fatal(err)
	}
	logicalRoot := filepath.Join(packageRoot, "var")
	writeExecutable := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(mockBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable("id", "#!/bin/sh\ncase \"$1\" in\n  -u) echo 0 ;;\n  -gn) echo synocommunity ;;\n  *) exit 0 ;;\nesac\n")
	writeExecutable("readlink", "#!/bin/sh\n[ \"$1\" = -f ] && [ \"$2\" = \"$LOGICAL_ROOT\" ] || exit 1\nprintf '%s\\n' /usr/local/packages/@appdata/dnsacme\n")
	writeExecutable("chown", "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$CHOWN_LOG\"\n")

	helper, err := filepath.Abs("synology/spk/scripts/repair-ownership")
	if err != nil {
		t.Fatal(err)
	}
	chownLog := filepath.Join(tempDir, "chown.log")
	cmd := exec.Command("sh", "-c", `. "$1"; PACKAGE_ROOT=$2; repair_package_ownership`, "sh", helper, packageRoot)
	cmd.Env = append(os.Environ(),
		"PATH="+mockBin+":"+os.Getenv("PATH"),
		"LOGICAL_ROOT="+logicalRoot,
		"CHOWN_LOG="+chownLog,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mock ownership migration failed: %v: %s", err, output)
	}
	logData, err := os.ReadFile(chownLog)
	if err != nil {
		t.Fatal(err)
	}
	want := "-hR -P sc-dnsacme:synocommunity /usr/local/packages/@appdata/dnsacme\n"
	if string(logData) != want {
		t.Fatalf("chown invocation = %q, want %q", logData, want)
	}
}

func TestSynologyInstallAndUpgradeRepairOwnership(t *testing.T) {
	for _, path := range []string{
		"synology/spk/scripts/postinst",
		"synology/spk/scripts/postupgrade",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		if !strings.Contains(script, `. "${SCRIPT_DIR}/repair-ownership"`) {
			t.Errorf("%s does not source the ownership migration helper", path)
		}
		if !strings.Contains(script, "repair_package_ownership") {
			t.Errorf("%s does not run ownership migration", path)
		}
	}

	buildData, err := os.ReadFile("synology/build-spk.sh")
	if err != nil {
		t.Fatal(err)
	}
	buildScript := string(buildData)
	for _, name := range []string{"postinst", "postupgrade", "repair-ownership"} {
		if !strings.Contains(buildScript, `scripts/`+name+`"`) {
			t.Errorf("build script does not mark %s executable", name)
		}
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
