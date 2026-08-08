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

func TestSynologyPackageUsesCommunityIdentityWithoutRootHooks(t *testing.T) {
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
	if len(privilege.CtrlScript) != 0 {
		for _, override := range privilege.CtrlScript {
			t.Errorf("unexpected lifecycle identity override for %s: %s", override.Action, override.RunAs)
		}
	}
}

func TestSynologyPackageShipsUnprivilegedUpgradeHooks(t *testing.T) {
	for _, path := range []string{
		"synology/spk/scripts/preupgrade",
		"synology/spk/scripts/postupgrade",
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("required upgrade hook is missing: %s: %v", path, err)
			continue
		}
		if info.Mode()&0o111 == 0 {
			t.Errorf("upgrade hook is not executable: %s", path)
		}
		cmd := exec.Command(path)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("upgrade hook %s failed in isolation: %v\n%s", path, err, output)
		}
	}

	for _, path := range []string{
		"synology/spk/scripts/postinst",
		"synology/spk/scripts/repair-ownership",
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("root migration hook must not be shipped: %s", path)
		}
	}

	buildData, err := os.ReadFile("synology/build-spk.sh")
	if err != nil {
		t.Fatal(err)
	}
	buildScript := string(buildData)
	for _, name := range []string{"postinst", "repair-ownership"} {
		if strings.Contains(buildScript, `scripts/`+name+`"`) {
			t.Errorf("build script still references root migration hook %s", name)
		}
	}
}

func TestSynologyUninstallRequiresExplicitDeleteChoice(t *testing.T) {
	data, err := os.ReadFile("synology/spk/scripts/postuninst")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if !strings.Contains(script, `${SYNOPKG_PKG_STATUS:-}`) {
		t.Fatal("postuninst must safely handle an unset package status")
	}
	if !strings.Contains(script, `${wizard_delete_data:-false}`) {
		t.Fatal("postuninst must require the explicit delete-data wizard choice")
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

func TestSynologyUninstallWizardKeepsDataByDefault(t *testing.T) {
	data, err := os.ReadFile("synology/spk/WIZARD_UIFILES/uninstall_uifile")
	if err != nil {
		t.Fatal(err)
	}
	var steps []struct {
		Items []struct {
			Type     string `json:"type"`
			Subitems []struct {
				Key          string `json:"key"`
				DefaultValue *bool  `json:"defaultValue"`
			} `json:"subitems"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &steps); err != nil {
		t.Fatalf("invalid uninstall wizard manifest: %v", err)
	}

	defaults := make(map[string]*bool)
	counts := make(map[string]int)
	for _, step := range steps {
		for _, item := range step.Items {
			for _, subitem := range item.Subitems {
				if subitem.Key != "wizard_keep_data" && subitem.Key != "wizard_delete_data" {
					continue
				}
				if item.Type != "singleselect" {
					t.Errorf("%s parent type = %q, want singleselect", subitem.Key, item.Type)
				}
				counts[subitem.Key]++
				defaults[subitem.Key] = subitem.DefaultValue
			}
		}
	}
	for _, key := range []string{"wizard_keep_data", "wizard_delete_data"} {
		if counts[key] != 1 {
			t.Errorf("uninstall wizard contains %d %s entries, want exactly 1", counts[key], key)
		}
	}
	keepData, ok := defaults["wizard_keep_data"]
	if !ok {
		t.Fatal("uninstall wizard is missing wizard_keep_data")
	}
	if keepData == nil {
		t.Fatal("wizard_keep_data must declare a default value")
	}
	if !*keepData {
		t.Fatal("uninstall wizard must keep package data by default")
	}
	deleteData, ok := defaults["wizard_delete_data"]
	if !ok {
		t.Fatal("uninstall wizard is missing wizard_delete_data")
	}
	if deleteData == nil {
		t.Fatal("wizard_delete_data must declare a default value")
	}
	if *deleteData {
		t.Fatal("uninstall wizard must not delete package data by default")
	}
}

func TestSynologyResourceManifestIsEmptyJSONObject(t *testing.T) {
	data, err := os.ReadFile("synology/spk/conf/resource")
	if err != nil {
		t.Fatal(err)
	}
	var resource map[string]any
	if err := json.Unmarshal(data, &resource); err != nil {
		t.Fatalf("invalid resource manifest: %v", err)
	}
	if resource == nil {
		t.Fatal("resource manifest must be a JSON object")
	}
	if len(resource) != 0 {
		t.Fatalf("resource manifest must be empty, got %v", resource)
	}
}

func TestSynologyBuildUsesCompatibleAMD64AndPackagesWizard(t *testing.T) {
	data, err := os.ReadFile("synology/build-spk.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if !strings.Contains(script, "build_pkg amd64 v1 x86_64") {
		t.Fatal("amd64 SPK must target GOAMD64 v1 for older x86_64 systems")
	}
	copyRE := regexp.MustCompile(`(?m)^\s*cp -R "\$ROOT/synology/spk/WIZARD_UIFILES/\." "\$work/WIZARD_UIFILES/?"\s*$`)
	if !copyRE.MatchString(script) {
		t.Fatal("build script must copy the uninstall wizard into the package workspace")
	}
	normalized := strings.ReplaceAll(script, "\\\n", " ")
	archiveRE := regexp.MustCompile(`(?m)^\s*\(cd "\$work" && tar -cf "\$pkg" [^\n]*\bWIZARD_UIFILES\b[^\n]*\)\s*$`)
	if !archiveRE.MatchString(normalized) {
		t.Fatal("top-level SPK archive must include WIZARD_UIFILES")
	}
}

func TestTaskfileSynologySpksrcBuildIsOptionalAndValidated(t *testing.T) {
	data, err := os.ReadFile("Taskfile.yaml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	spksrcTask := taskfileTaskBlock(t, source, "synology-spksrc")

	cliEnvRE := regexp.MustCompile(`(?m)^\s+SPKSRC_TARGET:\s*(?:"\{\{\.CLI_ARGS\}\}"|'\{\{\.CLI_ARGS\}\}')\s*$`)
	if !cliEnvRE.MatchString(spksrcTask) {
		t.Fatal("synology-spksrc must inject CLI_ARGS only through the SPKSRC_TARGET task environment")
	}
	if count := strings.Count(spksrcTask, ".CLI_ARGS"); count != 1 {
		t.Fatalf("synology-spksrc contains %d CLI_ARGS references, want only the SPKSRC_TARGET environment binding", count)
	}

	normalized := strings.Join(strings.Fields(spksrcTask), " ")
	for _, marker := range []string{
		`--platform=linux/amd64`,
		`-w /spksrc`,
		`-e "TAR_CMD=fakeroot tar"`,
	} {
		if !strings.Contains(normalized, marker) {
			t.Errorf("synology-spksrc Docker invocation is missing %q", marker)
		}
	}
	const targetPattern = `^arch-[a-z0-9]+-[0-9]+(\.[0-9]+)+$`
	targetValidationRE := regexp.MustCompile(`if ! printf ['"]%s\\n['"] "\$target" \| grep -Eq ['"]` + regexp.QuoteMeta(targetPattern) + `['"]; then`)
	targetValidation := targetValidationRE.FindStringIndex(normalized)
	if targetValidation == nil {
		t.Fatal("synology-spksrc must validate the target value with the pinned architecture target regex")
	}
	imageValidationRE := regexp.MustCompile(`case "\$image" in ""\s*\|\s*-\*\s*\|\s*\*\[\[:space:\]\]\*\)`)
	imageValidation := imageValidationRE.FindStringIndex(normalized)
	if imageValidation == nil {
		t.Fatal("synology-spksrc must reject empty, option-like, and whitespace-containing image values")
	}
	if strings.Contains(spksrcTask, `^[A-Za-z0-9][A-Za-z0-9._/@:-]*$`) {
		t.Fatal("synology-spksrc must not restrict valid registry references with a character whitelist")
	}
	dockerRun := strings.Index(normalized, "docker run")
	if dockerRun < 0 {
		t.Fatal("synology-spksrc is missing the Docker invocation")
	}
	if targetValidation[0] > dockerRun || imageValidation[0] > dockerRun {
		t.Fatal("synology-spksrc must validate the target and image before invoking Docker")
	}
	if !strings.Contains(normalized, `test -f "$SPKSRC_DIR/spk/dnsacme/Makefile"`) &&
		!strings.Contains(normalized, `[ -f "$SPKSRC_DIR/spk/dnsacme/Makefile" ]`) &&
		!strings.Contains(normalized, `test -f "$spksrc_input/spk/dnsacme/Makefile"`) &&
		!strings.Contains(normalized, `[ -f "$spksrc_input/spk/dnsacme/Makefile" ]`) {
		t.Fatal("synology-spksrc must validate SPKSRC_DIR/spk/dnsacme/Makefile as a read-only input")
	}
	if strings.Contains(spksrcTask, "cd --") {
		t.Fatal("synology-spksrc must not use cd -- because macOS /bin/sh does not support it")
	}
	pathCaseRE := regexp.MustCompile(`case "\$SPKSRC_DIR" in /\*\) spksrc_input="?\$SPKSRC_DIR"? ;; \*\) spksrc_input="?\$PWD/\$SPKSRC_DIR"? ;; esac`)
	caseLocation := pathCaseRE.FindStringIndex(normalized)
	if caseLocation == nil {
		t.Fatal("synology-spksrc must preserve absolute SPKSRC_DIR values and prefix relative values with $PWD/")
	}
	const resolveCommand = `spksrc_dir=$(CDPATH= cd "$spksrc_input" && pwd)`
	resolveLocation := strings.Index(normalized, resolveCommand)
	if resolveLocation < 0 {
		t.Fatal("synology-spksrc must resolve the normalized input with portable CDPATH= cd")
	}
	if caseLocation[0] > resolveLocation {
		t.Fatal("synology-spksrc must normalize SPKSRC_DIR before resolving it")
	}
	commaGuardRE := regexp.MustCompile(`case "\$spksrc_input" in \*,\*\)`)
	commaGuard := commaGuardRE.FindStringIndex(normalized)
	if commaGuard == nil {
		t.Fatal("synology-spksrc must reject commas that are ambiguous in Docker --mount source paths")
	}
	if commaGuard[0] > dockerRun {
		t.Fatal("synology-spksrc must reject ambiguous mount paths before invoking Docker")
	}
	if !strings.Contains(normalized, `"$image" make -C spk/dnsacme "$target"`) {
		t.Fatal("synology-spksrc must pass the validated image to Docker as a quoted argument")
	}
	if !strings.Contains(normalized, `--mount "type=bind,source=$spksrc_dir,target=/spksrc"`) {
		t.Fatal("synology-spksrc must pass the bind mount as one quoted --mount argument")
	}
	if strings.Contains(normalized, `-v "$spksrc_dir:/spksrc"`) {
		t.Fatal("synology-spksrc must not use the ambiguous short -v bind mount form")
	}
	if !strings.Contains(normalized, `make -C spk/dnsacme "$target"`) {
		t.Fatal("synology-spksrc must invoke the selected spksrc architecture target")
	}

	releaseBuild := taskfileTaskBlock(t, source, "release-build")
	if strings.Contains(releaseBuild, "synology-spksrc") {
		t.Fatal("release-build must not depend on the optional external spksrc build")
	}
}

func TestSynologyPostUninstallDataRetention(t *testing.T) {
	sourceBytes, err := os.ReadFile("synology/spk/scripts/postuninst")
	if err != nil {
		t.Fatal(err)
	}
	const packageRoot = "/var/packages/dnsacme"
	source := string(sourceBytes)
	if count := strings.Count(source, packageRoot); count != 3 {
		t.Fatalf("postuninst contains %d package root literals, want exactly 3 before isolated execution", count)
	}

	tests := []struct {
		name       string
		status     string
		deleteData string
		wantEmpty  bool
	}{
		{name: "variables unset"},
		{name: "uninstall keeps data", status: "UNINSTALL", deleteData: "false"},
		{name: "upgrade never deletes", status: "UPGRADE", deleteData: "true"},
		{name: "explicit uninstall deletion", status: "UNINSTALL", deleteData: "true", wantEmpty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caseRoot := t.TempDir()
			isolatedRoot := filepath.Join(caseRoot, "package's data")
			patched := strings.ReplaceAll(source, packageRoot, shellSingleQuote(isolatedRoot))
			if strings.Contains(patched, packageRoot) {
				t.Fatal("refusing to execute postuninst with a real DSM package path")
			}

			dirs := []string{"var", "etc", "home"}
			for _, name := range dirs {
				dir := filepath.Join(isolatedRoot, name)
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				for _, file := range []string{"visible", ".hidden", "..hidden"} {
					if err := os.WriteFile(filepath.Join(dir, file), []byte("test"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}

			scriptPath := filepath.Join(caseRoot, "postuninst")
			if err := os.WriteFile(scriptPath, []byte(patched), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(scriptPath)
			cmd.Env = []string{"PATH=/usr/bin:/bin"}
			if tt.status != "" {
				cmd.Env = append(cmd.Env, "SYNOPKG_PKG_STATUS="+tt.status)
			}
			if tt.deleteData != "" {
				cmd.Env = append(cmd.Env, "wizard_delete_data="+tt.deleteData)
			}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("isolated postuninst failed: %v\n%s", err, output)
			}

			for _, name := range dirs {
				dir := filepath.Join(isolatedRoot, name)
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatalf("postuninst removed %s directory: %v", name, err)
				}
				if tt.wantEmpty && len(entries) != 0 {
					t.Errorf("%s directory contains %d entries after explicit deletion", name, len(entries))
				}
				if !tt.wantEmpty && len(entries) != 3 {
					t.Errorf("%s directory contains %d entries, want retained visible and hidden files", name, len(entries))
				}
			}
		})
	}
}

func TestSynologyPackageVersionSkipsNonSemanticTags(t *testing.T) {
	helper, err := filepath.Abs("synology/package-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	runGit(t, repo, "init", "--quiet")
	runGit(t, repo, "config", "user.name", "DNSACME Test")
	runGit(t, repo, "config", "user.email", "dnsacme@example.invalid")
	if err := os.WriteFile(filepath.Join(repo, "tracked"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", "tracked")
	runGit(t, repo, "commit", "--quiet", "-m", "base")
	runGit(t, repo, "tag", "v1.2.3")

	if got := runPackageVersion(t, helper, repo); got != "1.2.3" {
		t.Fatalf("version at release tag = %q, want %q", got, "1.2.3")
	}

	runGit(t, repo, "commit", "--quiet", "--allow-empty", "-m", "ahead")
	runGit(t, repo, "tag", "release-candidate")
	runGit(t, repo, "tag", "v1.2.3-beta")
	runGit(t, repo, "tag", "v01.2.3")
	if got := runPackageVersion(t, helper, repo); got != "1.2.3-1" {
		t.Fatalf("version behind non-semantic tags = %q, want %q", got, "1.2.3-1")
	}
}

func runPackageVersion(t *testing.T, helper, repo string) string {
	t.Helper()
	cmd := exec.Command("sh", helper, repo)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("package version helper failed: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(output))
}

func runGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmdArgs := append([]string{"-C", repo}, args...)
	cmd := exec.Command("git", cmdArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func taskfileTaskBlock(t *testing.T, source, name string) string {
	t.Helper()
	marker := "  " + name + ":\n"
	start := strings.Index(source, marker)
	if start < 0 {
		t.Fatalf("Taskfile.yaml is missing the %s task", name)
	}
	block := source[start+len(marker):]
	nextTaskRE := regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:\s*$`)
	if next := nextTaskRE.FindStringIndex(block); next != nil {
		block = block[:next[0]]
	}
	return block
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
		"height: 740,",
		"minHeight: 740,",
		"FORM_COLUMN_OFFSET: 20,",
		"Math.min(me.FORM_COLUMN_OFFSET, Math.max(0, gutter - me.COLUMN_GUTTER))",
		`paddingLeft: leftGutter + "px", paddingRight: rightGutter + "px"`,
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

func TestSynologyUIProviderSwitchPreservesDraftAndAvoidsSideErrorIcons(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		"me.providerDrafts = {};",
		"me.renderedProviderName = null;",
		"if (!me._skipProviderDraftCapture) { me.captureProviderDraft(); }",
		"Object.prototype.hasOwnProperty.call(draft.config, f.key)",
		"configuredProvider === prov.name && me.cfg.dns.config && me.cfg.dns.config[f.key]",
		"captureProviderDraft: function () {",
		"config[field.providerKey] = field.getValue();",
		"draft.resolverText = me.fAcmeDNSResolvers.getValue();",
		"acmeDNSDraft.resolverText !== undefined",
		"me._skipProviderDraftCapture = true;",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("provider draft preservation is missing %q", marker)
		}
	}
	if strings.Count(source, `msgTarget: "qtip"`) < 2 {
		t.Fatal("dynamic provider fields still use side error icons that outlive destroyed elements")
	}
	start := strings.Index(source, "  renderProviderFields: function () {")
	end := strings.Index(source[start:], "\n\n  captureProviderDraft:")
	if start < 0 || end < 0 {
		t.Fatal("dynamic provider render block not found")
	}
	if strings.Contains(source[start:start+end], `msgTarget: "side"`) {
		t.Fatal("dynamic provider fields still create side error icons")
	}
}

func TestSynologyUIProviderSwitchOverridesParentValidationDefaultAfterInsertion(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`useTooltipValidation: function (field) {`,
		`if (field) { field.msgTarget = "qtip"; }`,
		"target.add(field);\n        // Container defaults are applied during add()",
		"me.useTooltipValidation(field);",
		"target.insert(serverIndex + 2, me.acmeDNSPanel);\n    // The parent form applies its \"side\" default during insert()",
		"me.useTooltipValidation(me.fAcmeDNSServer);",
		"me.useTooltipValidation(me.acmeDNSRegisterRow);",
		"me.useTooltipValidation(me.fAcmeDNSResolvers);",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("dynamic validation target is not restored after parent insertion: %q", marker)
		}
	}
}

func TestSynologyUIAcmeDNSRegistrationSurvivesProviderSwitch(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "  hydrateAcmeDNSAccount: function (account, server) {")
	end := strings.Index(source[start:], "\n\n  // Mask the whole panel")
	if start < 0 || end < 0 {
		t.Fatal("ACME-DNS account hydration block not found")
	}
	block := source[start : start+end]
	storeDraft := strings.Index(block, `this.mergeProviderDraftConfig("acmedns", values);`)
	hydrateFields := strings.Index(block, "Ext.each(this.providerFields")
	if storeDraft < 0 || hydrateFields < 0 || storeDraft > hydrateFields {
		t.Fatal("registration credentials are not stored in the ACME-DNS draft before current fields are hydrated")
	}
	for _, marker := range []string{
		`mergeProviderDraftConfig: function (providerName, values) {`,
		"draft.config = draft.config || {};",
		"Ext.apply(draft.config, values || {});",
		"disabled: !!me._acmeDNSRegistering,",
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("provider-switch-safe ACME-DNS registration is missing %q", marker)
		}
	}
}

func TestSynologyUIProviderDraftsOwnSelectedConfigCollection(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)

	captureStart := strings.Index(source, "  captureProviderDraft: function () {")
	captureEnd := strings.Index(source[captureStart:], "\n\n  mergeProviderDraftConfig:")
	if captureStart < 0 || captureEnd < 0 {
		t.Fatal("captureProviderDraft block not found")
	}
	capture := source[captureStart : captureStart+captureEnd]
	for _, marker := range []string{
		"var draft = me.providerDrafts[providerName] || {};",
		"var config = {};",
		"config[field.providerKey] = field.getValue();",
		"draft.config = config;",
		"draft.resolverText = me.fAcmeDNSResolvers.getValue();",
	} {
		if !strings.Contains(capture, marker) {
			t.Fatalf("provider draft capture does not preserve metadata while replacing current config: %q", marker)
		}
	}

	collectStart := strings.Index(source, "  collectConfig: function () {")
	collectEnd := strings.Index(source[collectStart:], "\n\n  save: function")
	if collectStart < 0 || collectEnd < 0 {
		t.Fatal("collectConfig block not found")
	}
	collect := source[collectStart : collectStart+collectEnd]
	for _, marker := range []string{
		"me.captureProviderDraft();",
		"var selectedProvider = me.fProvider.getValue();",
		"var selectedDraft = me.providerDrafts[selectedProvider] || { config: {} };",
		"var dnsConfig = Ext.apply({}, selectedDraft.config || {});",
		"if (selectedProvider === \"acmedns\") {",
		"(selectedDraft.resolverText || \"\").split(\",\")",
		"dns: { provider: selectedProvider, config: dnsConfig, resolvers: resolvers }",
	} {
		if !strings.Contains(collect, marker) {
			t.Fatalf("collectConfig does not derive the request from the selected provider draft: %q", marker)
		}
	}
	if strings.Contains(collect, "cfg.dns.config") {
		t.Fatal("collectConfig falls back to a non-current provider config")
	}

	renderStart := strings.Index(source, "  renderProviderFields: function () {")
	renderEnd := strings.Index(source[renderStart:], "\n\n  captureProviderDraft:")
	if renderStart < 0 || renderEnd < 0 {
		t.Fatal("renderProviderFields block not found")
	}
	render := source[renderStart : renderStart+renderEnd]
	configuredProvider := strings.Index(render, "var configuredProvider = me.cfg && me.cfg.dns && me.cfg.dns.provider;")
	persistedFallback := strings.Index(render, "configuredProvider === prov.name && me.cfg.dns.config && me.cfg.dns.config[f.key]")
	if configuredProvider < 0 || persistedFallback < 0 || configuredProvider > persistedFallback {
		t.Fatal("provider fields may hydrate an unselected provider from the configured provider's persisted config")
	}
}

func TestSynologyUIHTTP0ReconciliationRequiresOperationChange(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)

	fingerprintStart := strings.Index(source, "  operationStateFingerprint: function (action, source) {")
	fingerprintEnd := strings.Index(source[fingerprintStart:], "\n\n  reconcileActionState:")
	if fingerprintStart < 0 || fingerprintEnd < 0 {
		t.Fatal("operationStateFingerprint block not found")
	}
	fingerprint := source[fingerprintStart : fingerprintStart+fingerprintEnd]
	if !strings.Contains(fingerprint, `return [operation.success ? "1" : "0", String(operation.at || ""), String(operation.message || "")].join("\n");`) {
		t.Fatal("operation fingerprint must include normalized success, at, and message")
	}

	runStart := strings.Index(source, "  runAction: function (action) {")
	runEnd := strings.Index(source[runStart:], "\n\n  // finishAction")
	if runStart < 0 || runEnd < 0 {
		t.Fatal("runAction block not found")
	}
	run := source[runStart : runStart+runEnd]
	baseline := strings.Index(run, "var operationBaseline = me.operationStateFingerprint(action, me.cfg);")
	request := strings.Index(run, `SYNO.SDS.DNSACME.request(action, "POST", { editToken: me.configEditToken }`)
	if baseline < 0 || request < 0 || baseline > request {
		t.Fatal("runAction must capture the operation fingerprint after save and before the action request")
	}
	if !strings.Contains(run, "me.reconcileActionState(action, data, operationBaseline);") {
		t.Fatal("HTTP 0 reconciliation does not receive the pre-action operation fingerprint")
	}

	reconcileStart := strings.Index(source, "  reconcileActionState: function (action, errorText, operationBaseline) {")
	reconcileEnd := strings.Index(source[reconcileStart:], "\n\n  settleActionFailure:")
	if reconcileStart < 0 || reconcileEnd < 0 {
		t.Fatal("reconcileActionState block not found")
	}
	reconcile := source[reconcileStart : reconcileStart+reconcileEnd]
	for _, marker := range []string{
		"var currentOperation = ok ? me.operationState(action, data) : {};",
		"var operationChanged = ok && me.operationStateFingerprint(action, data) !== operationBaseline;",
		"var completed = operationChanged && currentOperation.success && (",
		"if (operationChanged) {",
		"me.settleActionFailure(action, data, errorText);",
		"me.settleActionFailure(action, null, ok ? errorText : data);",
	} {
		if !strings.Contains(reconcile, marker) {
			t.Fatalf("HTTP 0 reconciliation does not distinguish changed operation state: %q", marker)
		}
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

func TestSynologyUIStatusReconciliationPreservesEditToken(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if !strings.Contains(source, `{ config: { lastTest: data.lastTest }, editToken: data.editToken }`) {
		t.Fatal("test-run status reconciliation drops the config edit token")
	}
}

func TestSynologyUIAcmeDNSResolversRoundTrip(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`"field.acmeDNSResolvers": "Recursive DNS"`,
		`"field.acmeDNSResolvers": "递归 DNS"`,
		`"placeholder.acmeDNSResolvers": "1.1.1.1, 8.8.8.8"`,
		`var resolverValue = acmeDNSDraft && acmeDNSDraft.resolverText !== undefined`,
		`: (resolverValues.join(", ") || "1.1.1.1");`,
		`fieldLabel: SYNO.SDS.DNSACME.t("field.acmeDNSResolvers") + "*"`,
		`dns: { provider: selectedProvider, config: dnsConfig, resolvers: resolvers }`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("ACME-DNS resolver UI is missing %q", marker)
		}
	}
}

func TestSynologyUIProviderCleanupPrecedesDynamicDestruction(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "  renderProviderFields: function () {")
	end := strings.Index(source[start:], "\n\n  acmeDNSField:")
	if start < 0 || end < 0 {
		t.Fatal("renderProviderFields block not found")
	}
	block := source[start : start+end]
	clear := strings.Index(block, "field.clearInvalid()")
	destroyComposite := strings.Index(block, "target.remove(me.acmeDNSRegisterRow, true)")
	if clear < 0 || destroyComposite < 0 || clear > destroyComposite {
		t.Fatal("provider validation state is not cleared before the ACME-DNS CompositeField is destroyed")
	}
	if !strings.Contains(block, "fieldsToClear = me.providerFields.slice(0)") {
		t.Fatal("cleanup does not include the nested ACME-DNS server field")
	}
	if !strings.Contains(block, "fieldsToClear.push(me.acmeDNSRegisterRow)") {
		t.Fatal("cleanup does not include the ACME-DNS CompositeField")
	}
}

func TestSynologyUIActionFailureSettlesWithoutFormRebuild(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`body && body.data`,
		`body = response.responseText ? Ext.decode(response.responseText) : null;`,
		`body.error || SYNO.SDS.DNSACME.t("error.requestFailed"), body.data`,
		`if (failureData) { me.settleActionFailure(action, failureData, data); }`,
		`me.settleActionFailure(action, null, ok ? errorText : data);`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("failure response settlement is missing %q", marker)
		}
	}
	start := strings.Index(source, "  settleActionFailure: function (action, data, fallback) {")
	end := strings.Index(source[start:], "\n\n  showActionFailure:")
	if start < 0 || end < 0 {
		t.Fatal("settleActionFailure block not found")
	}
	block := source[start : start+end]
	for _, marker := range []string{
		"me.setActionsBusy(false);",
		"me.configEditToken = data.editToken;",
		"me.loadLogs();",
		"me.showActionFailure(action, reason);",
	} {
		if !strings.Contains(block, marker) {
			t.Fatalf("local failure settlement is missing %q", marker)
		}
	}
	for _, forbidden := range []string{"loadAll(", "applyConfig(", "renderProviderFields("} {
		if strings.Contains(block, forbidden) {
			t.Fatalf("local failure settlement must not rebuild the form through %q", forbidden)
		}
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

func TestSynologyUIAcmeDNSRegistrationFillsTheNormalForm(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`SYNO.SDS.DNSACME.request("acmedns-register", "POST"`,
		`title: SYNO.SDS.DNSACME.t("dialog.acmeDNSTrustTitle")`,
		`buttons: Ext.MessageBox.YESNO`,
		`if (button === "yes") { me.registerAcmeDNS(server); }`,
		`handler: me.confirmAcmeDNSRegistration`,
		`me.hydrateAcmeDNSAccount(data, data.serverURL || server);`,
		`status.acmeDNSRegistered`,
		`It will not be saved until you click Next.`,
		`me.acmeDNSRegisterRow = new Ext.form.CompositeField({`,
		`fieldLabel: SYNO.SDS.DNSACME.t("field.acmeDNSServer") + "*",`,
		`me.fAcmeDNSServer.width = 205;`,
		`width: 380,`,
		`items: [me.fAcmeDNSServer, me.acmeDNSRegisterBtn]`,
		`target.insert(serverIndex, me.acmeDNSRegisterRow);`,
		`target.insert(serverIndex + 1, me.fAcmeDNSResolvers);`,
		`target.insert(serverIndex + 2, me.acmeDNSPanel);`,
		`me.acmeDNSCNAMEBox = me.acmeDNSPanel.items.itemAt(1);`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("explicit ACME-DNS registration flow is missing %q", marker)
		}
	}
	if !strings.Contains(source, `.dnsacme-acmedns-register-row .x-form-element { display:flex; align-items:center; }`) {
		t.Fatal("ACME-DNS register row does not keep the input and button aligned")
	}
	if !strings.Contains(source, `.dnsacme-acmedns-register-row { margin-left:-8px; }`) {
		t.Fatal("ACME-DNS register row does not cancel CompositeField's label padding")
	}
	if !strings.Contains(source, `.dnsacme-acmedns { margin:2px 0 12px 160px; width:380px; max-width:380px; box-sizing:border-box; }`) {
		t.Fatal("ACME-DNS details panel is not aligned and width-bounded")
	}
	if !strings.Contains(source, `border: false, width: 380, cls: "dnsacme-acmedns"`) {
		t.Fatal("ACME-DNS panel does not give ExtJS an explicit body width")
	}
	for _, marker := range []string{
		`.dnsacme-acmedns-copy-btn { flex:0 0 auto; min-width:48px; min-height:24px;`,
		`.dnsacme-acmedns-copy-btn:hover { background:#dce7f0; }`,
		`.dnsacme-acmedns-copy-btn:focus { outline:1px solid #057feb; outline-offset:1px; }`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("ACME-DNS copy button styling is missing %q", marker)
		}
	}
	if strings.Contains(source, "me.acmeDNSPanel.items.itemAt(2)") {
		t.Fatal("ACME-DNS panel still treats the register button as a second owner")
	}
	for _, marker := range []string{
		`ACMEDNS_USERNAME: { label: "field.acmeDNSUsername" }`,
		`ACMEDNS_PASSWORD: { label: "field.acmeDNSPassword" }`,
		`ACMEDNS_SUBDOMAIN: { label: "field.acmeDNSSubdomain", placeholder: "placeholder.acmeDNSSubdomain" }`,
		`ACMEDNS_FULLDOMAIN: { label: "field.acmeDNSFullDomain", placeholder: "placeholder.acmeDNSFullDomain" }`,
		`"placeholder.acmeDNSSubdomain": "注册返回的 subdomain, 如 8c72f60d"`,
		`"placeholder.acmeDNSFullDomain": "如 8c72f60d.auth.acme-dns.io"`,
		`fieldLabel: fieldLabel + (f.required ? "*" : "")`,
		`labelSeparator: ":"`,
		`labelPad: 8`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("localized ACME-DNS field guidance is missing %q", marker)
		}
	}
	if strings.Contains(source, `fieldLabel + (f.required ? " *" : "")`) {
		t.Fatal("required marker still has a gap before the asterisk")
	}
	for _, blockName := range []string{"loadAll: function", "save: function", "runAction: function"} {
		start := strings.Index(source, blockName)
		if start < 0 {
			t.Fatalf("%s block not found", blockName)
		}
		end := strings.Index(source[start+1:], "\n  },")
		if end < 0 {
			t.Fatalf("%s block end not found", blockName)
		}
		if strings.Contains(source[start:start+1+end], `"acmedns-register"`) {
			t.Fatalf("%s must not invoke ACME-DNS registration", blockName)
		}
	}
}

func TestSynologyUIFormLabelsReserveInputGap(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`SYNO.SDS.DNSACME.FORM_LABEL_GAP = SYNO.SDS.DNSACME.LOCALE === "zh-CN" ? 3 : 8;`,
		`".dnsacme-content-form .x-form-item-label { box-sizing:border-box; padding-right:" + SYNO.SDS.DNSACME.FORM_LABEL_GAP + "px !important; }"`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("form labels do not reserve a locale-aware input gap: %q", marker)
		}
	}
}

func TestSynologyUIAcmeDNSCNAMEIsLiveEscapedAndCopyable(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`var encodedSource = Ext.util.Format.htmlEncode(cname.source || "-");`,
		`var encodedTarget = Ext.util.Format.htmlEncode(cname.target || "-");`,
		`if (!cname.source || !cname.target) {`,
		`bindAcmeDNSCNAMEInput: function (field)`,
		`field.on("change", refresh, me);`,
		`cmp.getEl().on("input", refresh);`,
		`cmp.getEl().on("paste", refresh);`,
		`cmp.getEl().on("keyup", refresh);`,
		`if (field.rendered) { bindDOM(field); }`,
		`else { field.on("afterrender", bindDOM, me, { single: true }); }`,
		`class="dnsacme-acmedns-copy-btn"`,
		`copyAcmeDNSValue: function (value)`,
		`document.execCommand("copy")`,
		`var safeServer = Ext.util.Format.htmlEncode(server);`,
		`server: safeServer`,
		`This delegated server can satisfy DNS challenges and request certificates for this domain.`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("safe CNAME handoff is missing %q", marker)
		}
	}
}

func TestSynologyUIAcmeDNSCNAMERefreshesAfterPersistedFieldsHydrate(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	start := strings.Index(source, "  renderProviderFields: function () {")
	end := strings.Index(source[start:], "\n\n  acmeDNSField:")
	if start < 0 || end < 0 {
		t.Fatal("renderProviderFields block not found")
	}
	block := source[start : start+end]
	if strings.Count(block, "me.renderAcmeDNSCNAME();") < 2 {
		t.Fatal("persisted ACME-DNS fields do not refresh the CNAME preview after immediate and deferred hydration")
	}
	for _, marker := range []string{"field.setValue(field.providerStoredValue || \"\");", "Ext.defer(function () {"} {
		if !strings.Contains(block, marker) {
			t.Fatalf("persisted ACME-DNS hydration is missing %q", marker)
		}
	}
}

func TestSynologyUIAcmeDNSPanelLaysOutInsertedChildren(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	marker := "me.acmeDNSPanel.on(\"afterrender\", function (panel) {\n      panel.doLayout();\n    }, me, { single: true });"
	if !strings.Contains(source, marker) {
		t.Fatal("dynamically inserted ACME-DNS panel does not lay out its children after its own render")
	}
	if strings.Contains(source, "if (me.acmeDNSPanel) { me.acmeDNSPanel.doLayout(); }") {
		t.Fatal("ACME-DNS child layout still depends on the parent form already being rendered")
	}
}

func TestSynologyUIAcmeDNSCopyBindingAndReconfigureToken(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`me.acmeDNSCNAMEBox.on("afterrender", function (box) {`,
		`box.getEl().on("click", function (event) {`,
		`SYNO.SDS.DNSACME.request("reconfigure", "POST", { editToken: me.configEditToken }`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("ACME-DNS UI synchronization is missing %q", marker)
		}
	}
	reconfigureStart := strings.Index(source, "  reconfigure: function () {")
	reconfigureEnd := strings.Index(source[reconfigureStart:], "\n\n  enterReconfigureView:")
	if reconfigureStart < 0 || reconfigureEnd < 0 {
		t.Fatal("reconfigure block not found")
	}
	reconfigure := source[reconfigureStart : reconfigureStart+reconfigureEnd]
	conflict := strings.Index(reconfigure, `if (String(data).indexOf("configuration changed") >= 0) {`)
	reconcile := strings.Index(reconfigure, `SYNO.SDS.DNSACME.request("config", "GET", null`)
	if conflict < 0 || reconcile < 0 || conflict > reconcile {
		t.Fatal("reconfigure must handle edit-token conflict before HTTP-0 reconciliation")
	}
	for _, marker := range []string{
		`me.reconfigBtn.setDisabled(false);`,
		`me.setStatus(SYNO.SDS.DNSACME.t("status.configChanged"), true);`,
		`return;`,
	} {
		if !strings.Contains(reconfigure[conflict:reconcile], marker) {
			t.Fatalf("reconfigure conflict path is missing %q", marker)
		}
	}
	renderStart := strings.Index(source, "  renderAcmeDNSCNAME: function () {")
	renderEnd := strings.Index(source[renderStart:], "\n\n  copyAcmeDNSValue:")
	if renderStart < 0 || renderEnd < 0 {
		t.Fatal("renderAcmeDNSCNAME block not found")
	}
	if strings.Contains(source[renderStart:renderStart+renderEnd], `on("afterrender"`) {
		t.Fatal("CNAME copy binding depends on CNAME content instead of component render")
	}
}

func TestSynologyUIAcmeDNSHasNoRecoveryModesOrCloseAutosave(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, removed := range []string{
		`me.save();`,
		`acmeDNSMode`,
		`_acmeDNSRecovery`,
		`setAcmeDNSMode`,
		`acmeDNSManual`,
		`recoveryRequiresReload`,
		`showAcmeDNSHandoff`,
	} {
		if strings.Contains(source, removed) {
			t.Fatalf("removed ACME-DNS recovery behavior remains: %q", removed)
		}
	}
}

func TestSynologyUIUsesEditTokensAndPreservesStaleFormFields(t *testing.T) {
	data, err := os.ReadFile("synology/spk/ui/DNSACME.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, marker := range []string{
		`editToken: me.configEditToken,`,
		`request(action, "POST", { editToken: me.configEditToken }`,
		`me.configEditToken = data.editToken;`,
		`me.configEditToken = reloadData.editToken;`,
		`data.editToken !== undefined`,
	} {
		if !strings.Contains(source, marker) {
			t.Fatalf("edit token transport is missing %q", marker)
		}
	}
	if strings.Contains(source, "configRevision") || strings.Contains(source, "revision:") {
		t.Fatal("abandoned revision transport remains in the UI")
	}
	start := strings.Index(source, "  save: function (cb, scope, opts) {")
	end := strings.Index(source[start:], "\n\n  requestAction:")
	if start < 0 || end < 0 {
		t.Fatal("save block not found")
	}
	block := source[start : start+end]
	failureEnd := strings.Index(block, "      me.markStepClean(me.step);")
	if failureEnd < 0 {
		t.Fatal("save failure branch end not found")
	}
	if strings.Contains(block[:failureEnd], "me.applyConfig(") || strings.Contains(block[:failureEnd], `request("config", "GET"`) {
		t.Fatal("failed save refreshes the form and can discard a newly registered account")
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
