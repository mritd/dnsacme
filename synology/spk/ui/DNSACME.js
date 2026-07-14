Ext.ns("SYNO.SDS.DNSACME");

// Source/package cache marker used to confirm that DSM loaded the rebuilt UI.
SYNO.SDS.DNSACME.BUILD = 92;

// DSM's protected package-app route is the CGI trust boundary; this same-origin
// URL does not implement separate browser authentication.
SYNO.SDS.DNSACME.API = "/webman/3rdparty/dnsacme/api.cgi";

// I18N_CATALOG_START
// Keep this catalog flat so static tests can verify locale parity and reject
// untranslated Chinese strings outside the localization boundary.
SYNO.SDS.DNSACME.I18N = {
  en: {
    "step.certificate": "Certificate",
    "step.dns": "DNS Provider",
    "step.autoUpdate": "Auto Update",
    "step.validateApply": "Validate & Apply",
    "status.loadingConfig": "Loading configuration...",
    "button.previous": "Previous",
    "button.next": "Next",
    "button.testRun": "Test Run",
    "button.apply": "Apply",
    "button.reconfigure": "Reconfigure",
    "button.ok": "OK",
    "status.saveBeforeForward": "Save the current step with Next before continuing",
    "status.fixFields": "Correct the highlighted fields",
    "status.ready": "Ready",
    "field.domain": "Domain",
    "placeholder.domain": "example.com or *.example.com",
    "field.email": "Email",
    "field.keyType": "Key type",
    "field.issuer": "Issuer",
    "title.certificate": "Certificate",
    "subtitle.certificate": "Enter the domain and ACME account email",
    "validation.singleDomain": "Synology DSM deployment supports one domain at a time",
    "validation.invalidDomain": "Invalid domain: {domain}",
    "validation.domainRequired": "Enter one domain",
    "field.provider": "Provider",
    "title.dns": "DNS Provider",
    "subtitle.dns": "Choose a DNS provider and enter credentials for DNS-01 validation",
    "field.dsmAccount": "DSM account",
    "placeholder.dsmAccount": "DSM administrator account",
    "field.dsmPassword": "DSM password",
    "placeholder.dsmPassword": "DSM administrator password",
    "field.certificateDescription": "Certificate description",
    "option.createCertificate": "Create certificate if missing",
    "option.setDefault": "Set as default certificate",
    "field.host": "Host",
    "field.protocol": "Protocol",
    "field.port": "Port",
    "advanced.settings": "Advanced settings",
    "hint.detectionFailed": "DSM connection could not be detected. Confirm the protocol and port.",
    "title.autoUpdate": "Auto Update",
    "subtitle.autoUpdate": "Configure DSM sign-in and certificate deployment",
    "title.validateApply": "Validate & Apply",
    "subtitle.validateApply": "Optionally test with staging, or apply a production certificate directly",
    "title.running": "Auto Update Running",
    "summary.domain": "Domain",
    "summary.provider": "DNS Provider",
    "summary.keyType": "Key type",
    "summary.issuer": "Issuer",
    "summary.lastApplied": "Last applied",
    "status.loadFailed": "Load failed: {error}",
    "status.saving": "Saving...",
    "status.saveFailed": "Save failed: {error}",
    "status.saved": "Saved",
    "status.requestingStaging": "Requesting a staging certificate...",
    "status.requestingProduction": "Requesting a production certificate...",
    "status.stagingComplete": "Staging validation completed; wait at least 10 minutes before Apply",
    "status.productionApplied": "Production certificate applied",
    "status.openingConfiguration": "Opening configuration...",
    "status.reconfigureFailed": "Unable to start reconfiguration: {error}",
    "status.failed": "Failed: {reason}",
    "dialog.testFailed": "Test run failed",
    "dialog.applyFailed": "Apply failed",
    "dialog.testSuccessTitle": "Test run succeeded",
    "dialog.testSuccessBody": "The staging certificate was issued successfully and was not deployed to DSM. DNS resolvers may still cache its challenge record. Wait at least 10 minutes before Apply to reduce the chance of production validation seeing stale DNS data.",
    "dialog.applyUntestedTitle": "Apply without a test run?",
    "dialog.applyUntestedBody": "This configuration has not passed a staging test. Apply will request a production certificate immediately, and a validation failure may count against the certificate authority's production rate limits. Continue?",
    "dialog.applyRecentTestTitle": "DNS cache may still contain test data",
    "dialog.applyRecentTestBody": "The staging test completed less than 10 minutes ago. Applying now may fail if DNS resolvers still cache the staging challenge. Continue anyway?",
    "error.label": "Error",
    "error.dsmLogin": "Unable to sign in to DSM. Check the DSM address, account, and password.",
    "error.dnsValidation": "DNS validation failed. The TXT record may not have propagated to every DNS server yet. Wait a few minutes and try again.",
    "error.dnsProvider": "The DNS provider request failed. Check the provider credentials and permissions.",
    "error.caRateLimited": "The certificate authority has rate-limited this request. Retry after the time shown in the log.",
    "error.dsmImport": "The certificate was not imported into DSM. Check the certificate description and DSM account permissions.",
    "error.testGeneric": "The test run failed. Check the log for details.",
    "error.applyGeneric": "The certificate could not be applied. Check the log for details.",
    "error.requestFailed": "Request failed",
    "error.invalidResponse": "Invalid response",
    "error.http": "HTTP {status}"
  },
  "zh-CN": {
    "step.certificate": "证书",
    "step.dns": "DNS 提供商",
    "step.autoUpdate": "自动更新",
    "step.validateApply": "验证并应用",
    "status.loadingConfig": "正在加载配置...",
    "button.previous": "上一步",
    "button.next": "下一步",
    "button.testRun": "测试运行",
    "button.apply": "应用",
    "button.reconfigure": "重新配置",
    "button.ok": "确定",
    "status.saveBeforeForward": "请先点击'下一步'保存当前步骤",
    "status.fixFields": "请修正标红的字段",
    "status.ready": "就绪",
    "field.domain": "域名",
    "placeholder.domain": "example.com 或 *.example.com",
    "field.email": "邮箱",
    "field.keyType": "密钥类型",
    "field.issuer": "颁发机构",
    "title.certificate": "证书信息",
    "subtitle.certificate": "填写待申请的域名和 ACME 账户邮箱",
    "validation.singleDomain": "Synology DSM 每次只能部署一个域名",
    "validation.invalidDomain": "无效域名: {domain}",
    "validation.domainRequired": "请填写一个域名",
    "field.provider": "提供商",
    "title.dns": "DNS 提供商",
    "subtitle.dns": "选择 DNS 提供商并填写 DNS-01 验证凭据",
    "field.dsmAccount": "DSM 账号",
    "placeholder.dsmAccount": "DSM 管理员账号",
    "field.dsmPassword": "DSM 密码",
    "placeholder.dsmPassword": "DSM 管理员密码",
    "field.certificateDescription": "证书描述",
    "option.createCertificate": "不存在时创建证书",
    "option.setDefault": "设为默认证书",
    "field.host": "主机",
    "field.protocol": "协议",
    "field.port": "端口",
    "advanced.settings": "高级设置",
    "hint.detectionFailed": "未能自动探测本机 DSM 端口, 请确认协议和端口.",
    "title.autoUpdate": "自动更新",
    "subtitle.autoUpdate": "配置 DSM 登录和证书部署方式",
    "title.validateApply": "验证并应用",
    "subtitle.validateApply": "可选择测试运行, 也可以直接申请并应用正式证书",
    "title.running": "自动更新运行中",
    "summary.domain": "域名",
    "summary.provider": "DNS 提供商",
    "summary.keyType": "密钥类型",
    "summary.issuer": "颁发机构",
    "summary.lastApplied": "最近应用",
    "status.loadFailed": "加载失败: {error}",
    "status.saving": "正在保存...",
    "status.saveFailed": "保存失败: {error}",
    "status.saved": "已保存",
    "status.requestingStaging": "正在申请测试证书...",
    "status.requestingProduction": "正在申请正式证书...",
    "status.stagingComplete": "测试环境验证完成, 建议至少等待 10 分钟后再应用",
    "status.productionApplied": "正式证书已应用",
    "status.openingConfiguration": "正在打开配置...",
    "status.reconfigureFailed": "无法开始重新配置: {error}",
    "status.failed": "失败: {reason}",
    "dialog.testFailed": "测试运行失败",
    "dialog.applyFailed": "应用失败",
    "dialog.testSuccessTitle": "测试运行成功",
    "dialog.testSuccessBody": "测试证书已成功签发, 但不会部署到 DSM. DNS 解析器可能仍缓存测试 challenge 记录. 建议至少等待 10 分钟后再点击'应用', 以降低正式验证读取到旧 DNS 数据的概率.",
    "dialog.applyUntestedTitle": "不测试直接应用?",
    "dialog.applyUntestedBody": "当前配置尚未通过测试环境验证. '应用'会立即申请正式证书, 验证失败可能计入证书颁发机构的生产环境频率限制. 是否继续?",
    "dialog.applyRecentTestTitle": "DNS 缓存可能仍包含测试数据",
    "dialog.applyRecentTestBody": "测试运行完成尚不足 10 分钟. 如果 DNS 解析器仍缓存测试 challenge, 立即应用可能失败. 是否仍要继续?",
    "error.label": "错误",
    "error.dsmLogin": "DSM 无法登录, 请检查 DSM 地址, 账号和密码.",
    "error.dnsValidation": "DNS 验证失败, TXT 记录可能尚未同步到全部 DNS 节点, 请等待几分钟后重试.",
    "error.dnsProvider": "DNS 提供商请求失败, 请检查凭据和权限.",
    "error.caRateLimited": "证书颁发机构已限制请求频率, 请在日志提示的时间后重试.",
    "error.dsmImport": "证书未能导入 DSM, 请检查证书描述和 DSM 账号权限.",
    "error.testGeneric": "测试运行失败, 请查看日志了解详情.",
    "error.applyGeneric": "证书应用失败, 请查看日志了解详情.",
    "error.requestFailed": "请求失败",
    "error.invalidResponse": "响应格式无效",
    "error.http": "HTTP {status}"
  }
};
// I18N_CATALOG_END

// DSM's native translation function reflects the active user-session language,
// unlike navigator.language, which can remain unchanged when DSM is switched.
SYNO.SDS.DNSACME.resolveLocale = function () {
  if (typeof _T === "function") {
    try {
      var probe = _T("common", "cancel") || "";
      if (/[\u3400-\u9fff]/.test(probe)) { return "zh-CN"; }
      if (probe) { return "en"; }
    } catch (ignore) {}
  }
  var lang = (document.documentElement && document.documentElement.getAttribute("lang")) ||
    (navigator.languages && navigator.languages[0]) || navigator.language || navigator.userLanguage || "en";
  return /^zh(?:-|_|$)/i.test(lang) ? "zh-CN" : "en";
};

SYNO.SDS.DNSACME.LOCALE = SYNO.SDS.DNSACME.resolveLocale();

// t performs named placeholder replacement while preserving the English catalog
// as the fallback for missing keys and every unsupported DSM locale.
SYNO.SDS.DNSACME.t = function (key, values) {
  var catalog = SYNO.SDS.DNSACME.I18N[SYNO.SDS.DNSACME.LOCALE] || SYNO.SDS.DNSACME.I18N.en;
  var text = catalog[key] || SYNO.SDS.DNSACME.I18N.en[key] || key;
  return text.replace(/\{([A-Za-z0-9_]+)\}/g, function (match, name) {
    return values && values[name] !== undefined ? String(values[name]) : match;
  });
};

// One-time scoped CSS for the stepper, advanced section, log view, and footbar
// details that ExtJS and DSM's stock component skins cannot express directly.
SYNO.SDS.DNSACME.injectCss = function () {
  if (document.getElementById("dnsacme-style")) {
    return;
  }
  var css = [
    ".dnsacme-stepper { display:flex; justify-content:center; align-items:center; height:60px; padding:0 24px; border-bottom:1px solid #e8ecf1; background:#fff; }",
    ".dnsacme-stepper-inner { display:flex; align-items:center; width:100%; max-width:880px; }",
    ".dnsacme-step { display:flex; align-items:center; color:#8b95a1; font-size:14px; }",
    ".dnsacme-step.done, .dnsacme-step.active { color:#414b54; }",
    ".dnsacme-step.reachable { cursor:pointer; }",
    ".dnsacme-step-num { display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; border-radius:50%; margin-right:8px; background:#c6d4e0; color:#fff; font-size:13px; line-height:1; }",
    ".dnsacme-step.active .dnsacme-step-num { background:#057feb; }",
    ".dnsacme-step.done .dnsacme-step-num { background:#d8e9fc; color:#057feb; }",
    ".dnsacme-step-check { font-size:13px; line-height:1; }",
    ".dnsacme-step-sep { flex:1 1 auto; min-width:20px; height:1px; background:#dde4ea; margin:0 14px; }",
    ".dnsacme-adv-hint { color:#e6892b; font-size:12px; margin:4px 0 8px; }",
    /* Neutral inline note under a form field; left margin clears the 160px label column + 5px pad. */
    /* Advanced-option hints align flush-left with the checkboxes above them (no
       label-column indent) so every hint shares the options' left edge. */
    ".dnsacme-field-note { color:#8b95a1; font-size:12px; line-height:1.5; margin:2px 0 8px 0; max-width:560px; }",
    /* Amber marks a testing / caveat note; layout is inherited from -note. */
    ".dnsacme-field-warn { color:#c56a00; }",
    ".dnsacme-adv-toggle { display:flex; align-items:center; margin:20px 0 14px; color:#0b5f9f; font-weight:600; cursor:pointer; user-select:none; }",
    ".dnsacme-adv-toggle:after { content:''; height:1px; background:#86b3d4; flex:1; margin-left:14px; }",
    ".dnsacme-adv-arrow { display:inline-block; width:14px; margin-right:6px; color:#0b5f9f; }",
    ".dnsacme-adv-panel { padding-bottom:4px; }",
    ".dnsacme-dns-form .x-form-item-label { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }",
    ".dnsacme-win .x-window-header.x-panel-icon { background-image:url(/webman/3rdparty/dnsacme/images/dnsacme_48.png) !important; background-repeat:no-repeat !important; background-position:18px 8px !important; background-size:24px 24px !important; }",
    ".dnsacme-error-dialog { width:auto; max-width:100%; padding:0; color:#414b54; box-sizing:border-box; }",
    ".dnsacme-error-head { display:flex; align-items:center; margin-bottom:12px; }",
    ".dnsacme-error-icon { flex:0 0 32px; width:32px; height:32px; margin-right:14px; border-radius:50%; background:#fdecec; color:#e64040; font-size:19px; font-weight:700; line-height:32px; text-align:center; }",
    ".dnsacme-error-title { margin:0; color:#2c333a; font-size:16px; font-weight:700; line-height:1.35; }",
    ".dnsacme-error-message { margin:0 0 0 46px; color:#5f6b76; font-size:13px; line-height:1.65; white-space:normal; word-break:break-word; }",
    // The dialog now renders inside the app window's native message box, which
    // supplies its own rounded/shadowed chrome and OK button; icon:"" leaves an
    // empty native icon slot, so collapse it and let the body HTML own the layout.
    // Match DSM's native message box insets exactly (measured from its own
    // v-message-box-window on this DSM build): 24px above the content, 20px below
    // the OK button, and 30px on the left and right. The message box's footer table
    // is locked to a fixed width that parks the OK button ~60px from the right, and
    // that offset is constant regardless of message width, so a flat translateX
    // nudges the button out to the native 30px in every case.
    ".dnsacme-error-msgbox .x-window-body { padding:24px 30px 2px 30px !important; }",
    ".dnsacme-error-msgbox .ext-mb-icon { display:none !important; width:0 !important; margin:0 !important; }",
    ".dnsacme-error-msgbox .ext-mb-content { min-height:0 !important; padding:0 !important; }",
    ".dnsacme-error-msgbox .ext-mb-text { width:100% !important; min-height:0 !important; padding:0 !important; }",
    ".dnsacme-error-msgbox .dnsacme-error-head { margin-bottom:9px !important; }",
    ".dnsacme-error-msgbox .x-toolbar { padding:2px 6px 0 !important; }",
    ".dnsacme-error-msgbox .x-window-footer, .dnsacme-error-msgbox .x-panel-footer { padding:0 0 20px !important; margin:0 !important; }",
    ".dnsacme-error-msgbox .x-panel-fbar .syno-ux-button { transform:translateX(30px) !important; }",
    // The footer table clips its overflow, so the translated button would be cut
    // off at the table's right edge; let the footer chain overflow visibly so the
    // shifted button paints fully into the full-width body area (which does not clip
    // at 30px from the right edge).
    ".dnsacme-error-msgbox .x-panel-fbar, .dnsacme-error-msgbox .x-window-footer, .dnsacme-error-msgbox .x-toolbar-ct, .dnsacme-error-msgbox .x-toolbar, .dnsacme-error-msgbox .x-toolbar-right, .dnsacme-error-msgbox .x-toolbar-cell { overflow:visible !important; }",
    ".dnsacme-content { max-width:880px !important; margin:0 auto !important; }",
    // Form steps: shrink the centered card to hug its fields (labelWidth 160 +
    // field 380). At the full 880 the fields sat in the left half with a wide
    // dead gap on the right, reading as left-heavy; a snug column centers cleanly.
    // The log step keeps the full 880 so its output has room.
    ".dnsacme-content-form { max-width:580px !important; }",
    // Flat, DSM-native: a per-step title + muted subtitle above the fields, no
    // card frame. The log box is its own container, so a wrapping card just
    // reads as a redundant box-in-box.
    ".dnsacme-card-head { margin-bottom:18px; }",
    ".dnsacme-card-title { font-size:16px; font-weight:700; color:#2c333a; line-height:1.3; }",
    ".dnsacme-card-sub { font-size:12px; color:#8b95a1; margin-top:6px; line-height:1.45; }",
    ".dnsacme-card .x-form-item { margin-bottom:14px !important; }",
    // Log view: a plain <pre> we fully control -- exactly one scrollable element,
    // so no double scrollbar and native trackpad horizontal scroll.
    "pre.dnsacme-log { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; line-height:1.55; color:#414b54; background:#f7f9fb; white-space:pre; overflow:auto; padding:10px 12px; border:1px solid #d7e0ea; border-radius:6px; box-sizing:border-box; -moz-tab-size:4; tab-size:4; cursor:text; -webkit-user-select:text !important; user-select:text !important; }",
    ".dnsacme-log-error { color:#d93025; font-weight:600; }",
    ".dnsacme-log-warn { color:#c56a00; font-weight:600; }",
    ".dnsacme-hint { color:#8b95a1; font-size:12px; margin:2px 0 12px; }",
    ".dnsacme-deployed { color:#414b54; padding:4px 0 30px; }",
    ".dnsacme-deployed-title { font-size:18px; font-weight:700; color:#2c333a; margin-bottom:18px; }",
    ".dnsacme-deployed-grid { display:grid; grid-template-columns:repeat(2, minmax(240px, 1fr)); column-gap:36px; row-gap:10px; max-width:720px; }",
    ".dnsacme-deployed-line { font-size:13px; line-height:1.55; }",
    ".dnsacme-deployed-line span { color:#6f7b86; margin-right:6px; }",
    ".dnsacme-deployed-line b { color:#2c333a; }",
    // Bottom action bar + pill buttons, skinned to match DSM 7.2 (Vue) footbar.
    ".dnsacme-win .x-panel-bbar, .dnsacme-win .x-panel-bbar .x-toolbar, .dnsacme-win .x-panel-bbar .x-toolbar-ct { height:48px !important; }",
    ".dnsacme-win .x-panel-bbar .x-toolbar { border-top:1px solid rgba(198,212,224,0.5) !important; background:#fff !important; padding:0 16px !important; }",
    ".dnsacme-win .x-panel-bbar td.x-toolbar-cell { vertical-align:middle !important; padding:0 4px !important; }",
    ".dnsacme-win .syno-ux-button { border-radius:100px !important; min-width:80px !important; }",
    // DSM's ExtJS button is 24px tall. Matching that line box keeps Latin and
    // CJK glyphs optically centered instead of pushing their baseline down.
    ".dnsacme-win .syno-ux-button .x-btn-text { height:24px !important; padding:0 18px !important; font-size:13px !important; line-height:24px !important; }",
    ".dnsacme-status-error { color:#d93025 !important; font-weight:600 !important; }"
  ].join("\n");
  var style = document.createElement("style");
  style.id = "dnsacme-style";
  style.type = "text/css";
  style.appendChild(document.createTextNode(css));
  document.getElementsByTagName("head")[0].appendChild(style);
};

// Thin AJAX wrapper around the CGI's {success,data,error} envelope.
SYNO.SDS.DNSACME.request = function (action, method, data, cb, scope) {
  Ext.Ajax.request({
    url: SYNO.SDS.DNSACME.API + "?action=" + encodeURIComponent(action),
    method: method || "GET",
    jsonData: method === "POST" ? (data || {}) : undefined,
    // Exceed the Go operation context (20 minutes) so the CGI can return a
    // definitive envelope before the transport-level reconciliation path runs.
    timeout: 1500000,
    success: function (response) {
      var body;
      try {
        body = Ext.decode(response.responseText);
      } catch (e) {
        cb.call(scope, false, SYNO.SDS.DNSACME.t("error.invalidResponse"));
        return;
      }
      if (!body || !body.success) {
        cb.call(scope, false, (body && body.error) || SYNO.SDS.DNSACME.t("error.requestFailed"));
        return;
      }
      cb.call(scope, true, body.data);
    },
    failure: function (response) {
      cb.call(scope, false, SYNO.SDS.DNSACME.t("error.http", { status: response.status || 0 }));
    }
  });
};

// Local (client-side) combo box in DSM's native style.
SYNO.SDS.DNSACME.combo = function (cfg, pairs) {
  var data = [];
  Ext.each(pairs || [], function (p) { data.push({ v: p[0], t: p[1] }); });
  return new SYNO.ux.ComboBox(Ext.apply({
    editable: false,
    triggerAction: "all",
    mode: "local",
    forceSelection: true,
    valueField: "v",
    displayField: "t",
    store: new Ext.data.JsonStore({ fields: ["v", "t"], data: data })
  }, cfg));
};

Ext.define("SYNO.SDS.DNSACME.Application", {
  extend: "SYNO.SDS.AppInstance",
  appWindowName: "SYNO.SDS.DNSACME.MainWindow"
});

Ext.define("SYNO.SDS.DNSACME.MainWindow", {
  extend: "SYNO.SDS.AppWindow",
  width: 1000,
  height: 680,
  minWidth: 880,
  minHeight: 560,
  resizable: true,
  maximizable: true,

  constructor: function (config) {
    var me = this;
    me.providers = [];
    me.cfg = null;
    me.providerFields = [];
    me._closed = false;

    SYNO.SDS.DNSACME.injectCss();
    me.buildUI();

    var windowConfig = Ext.apply({
      title: "DNSACME",
      cls: "dnsacme-win",
      layout: "fit",
      items: [me.mainPanel]
    }, config || {});

    // DSM may restore a window size saved by an older package build, including
    // dimensions smaller than this UI can render. Ext.Window's minWidth and
    // minHeight constrain later drag-resizes but do not repair that initial
    // config, so clamp it before the first layout while still fitting small
    // browser viewports.
    me.fitInitialWindowSize(windowConfig);

    this.callParent([windowConfig]);

    // Persist a dirty step on close as a best effort; callbacks ignore the
    // destroyed window while the CGI request can still complete independently.
    this.on("beforedestroy", function () {
      if (me.isCurrentStepDirty()) { me.save(); } // persist current-step edits
      me._closed = true;
      me.stopLogs();
      if (me.mainPanel && me.mainPanel.el) { me.mainPanel.el.unmask(); }
    }, this);
    // The log <pre> has no room to scroll the card region (autoScroll:false), so a
    // fixed height clipped its last line on shorter windows. Refit it to fill the
    // remaining height whenever the card region resizes. Hooking the region's own
    // "resize" (not the window's) guarantees the border layout has already applied
    // the new geometry; the one-tick defer lets the region body settle first.
    me.cards.on("resize", function () { me.fitLogHeight.defer(1, me); }, me);
    // Ext's nested auto layouts keep the width from their first render. Force a
    // complete layout pass after an outer window resize so a card initially
    // rendered in a restored narrow window expands instead of staying clipped.
    this.on("resize", function () { me.reflowWindowLayout.defer(1, me); }, this);
    // AppWindow can render during callParent. Start immediately in that case;
    // otherwise wait for the one afterrender event that is still pending.
    var start = function () { me.reflowWindowLayout(); me.showStep(0); me.maskMain(SYNO.SDS.DNSACME.t("status.loadingConfig")); me.loadAll(); };
    if (me.rendered) { start(); } else { me.on("afterrender", start, me, { single: true }); }
  },

  fitInitialWindowSize: function (config) {
    var view = Ext.getBody && Ext.getBody().getViewSize ? Ext.getBody().getViewSize() : null;
    var margin = 32;
    var maxWidth = view && view.width > 0 ? Math.max(320, view.width - margin) : Number.MAX_VALUE;
    var maxHeight = view && view.height > 0 ? Math.max(320, view.height - margin) : Number.MAX_VALUE;
    var minWidth = Math.min(this.minWidth, maxWidth);
    var minHeight = Math.min(this.minHeight, maxHeight);
    var requestedWidth = parseInt(config.width, 10) || this.width;
    var requestedHeight = parseInt(config.height, 10) || this.height;

    config.minWidth = minWidth;
    config.minHeight = minHeight;
    config.width = Math.max(minWidth, Math.min(requestedWidth, maxWidth));
    config.height = Math.max(minHeight, Math.min(requestedHeight, maxHeight));
  },

  reflowWindowLayout: function () {
    if (!this.rendered) { return; }
    if (this.mainPanel && this.mainPanel.rendered) { this.mainPanel.doLayout(); }
    if (this.cards && this.cards.rendered) { this.cards.doLayout(); }
    var layout = this.cards && this.cards.getLayout ? this.cards.getLayout() : null;
    var active = layout && layout.activeItem;
    if (active && active.doLayout) { active.doLayout(); }
    this.fitLogHeight.defer(1, this);
  },

  STEPS: [
    { id: "certificate", text: SYNO.SDS.DNSACME.t("step.certificate") },
    { id: "dns", text: SYNO.SDS.DNSACME.t("step.dns") },
    { id: "synology", text: SYNO.SDS.DNSACME.t("step.autoUpdate") },
    { id: "validation", text: SYNO.SDS.DNSACME.t("step.validateApply") }
  ],

  buildUI: function () {
    var me = this;
    // step is the visible card; progressStep is the highest card unlocked by a
    // completed predecessor save. A dirty card may move backward but not forward.
    // deployedMode shows the running summary, while forceWizard mirrors the
    // persisted reconfiguration state so canRenew cannot redirect back to it.
    me.step = 0;
    me.progressStep = 0;
    me.deployedMode = false;
    me.forceWizard = false;
    me.stepForms = [];

    me.cardItems = [me.buildCertificate(), me.buildDns(), me.buildSynology(), me.buildValidation()];
    me.deployedCard = me.buildDeployed();
    me.cards = new Ext.Panel({
      region: "center", layout: "card", activeItem: 0, border: false,
      items: me.cardItems.concat([me.deployedCard])
    });

    me.statusText = new Ext.Toolbar.TextItem(SYNO.SDS.DNSACME.t("status.loadingConfig"));
    me.prevBtn = new SYNO.ux.Button({ text: SYNO.SDS.DNSACME.t("button.previous"), handler: me.prev, scope: me });
    me.nextBtn = new SYNO.ux.Button({ text: SYNO.SDS.DNSACME.t("button.next"), btnStyle: "blue", handler: me.next, scope: me });
    me.testBtn = new SYNO.ux.Button({ text: SYNO.SDS.DNSACME.t("button.testRun"), handler: function () { me.requestAction("test-run"); } });
    me.applyBtn = new SYNO.ux.Button({ text: SYNO.SDS.DNSACME.t("button.apply"), btnStyle: "blue", handler: function () { me.requestAction("apply"); } });
    me.reconfigBtn = new SYNO.ux.Button({ text: SYNO.SDS.DNSACME.t("button.reconfigure"), handler: me.reconfigure, scope: me });

    me.mainPanel = new Ext.Panel({
      layout: "border", border: false,
      items: [me.buildStepper(), me.cards],
      bbar: new Ext.Toolbar({ items: [me.statusText, "->", me.prevBtn, me.nextBtn, me.testBtn, me.applyBtn, me.reconfigBtn] })
    });
  },

  buildStepper: function () {
    var me = this;
    me.stepper = new Ext.BoxComponent({
      region: "north", height: 60, autoEl: { tag: "div", cls: "dnsacme-stepper" }
    });
    me.stepper.on("afterrender", function () {
      me.renderStepper();
      me.stepper.getEl().on("click", function (e) {
        var t = me.findStepTarget(e.getTarget());
        if (!t) { return; }
        var i = parseInt(t.getAttribute("data-idx"), 10);
        if (isNaN(i)) { return; }
        if (me.canOpenStep(i)) {
          me.showStep(i);
        } else if (i > me.step && i <= me.progressStep && me.isCurrentStepDirty()) {
          me.setStatus(SYNO.SDS.DNSACME.t("status.saveBeforeForward"));
          me.renderStepper();
        }
      });
    }, me, { single: true });
    return me.stepper;
  },

  findStepTarget: function (node) {
    var root = this.stepper && this.stepper.getEl && this.stepper.getEl().dom;
    while (node && node !== root) {
      if ((" " + (node.className || "") + " ").indexOf(" dnsacme-step ") >= 0) {
        return node;
      }
      node = node.parentNode;
    }
    return null;
  },

  isCurrentStepDirty: function () {
    var dirty = false;
    this.eachContainerField(this.stepForms[this.step], function (f) {
      if (f.isDirty && f.isDirty()) { dirty = true; }
    });
    return dirty;
  },

  markStepClean: function (idx) {
    var form = this.stepForms[idx];
    if (!form) { return; }
    this.eachContainerField(form, function (f) {
      if (f.getValue) { f.originalValue = f.getValue(); }
    });
    this.renderStepper();
  },

  eachContainerField: function (ct, fn) {
    var me = this;
    if (!ct || !ct.items) { return; }
    ct.items.each(function (item) {
      if (item.getValue || item.validate) { fn(item); }
      me.eachContainerField(item, fn);
    });
  },

  canOpenStep: function (i) {
    if (i < 0 || i > this.progressStep) { return false; }
    if (i <= this.step) { return true; }
    return !this.isCurrentStepDirty();
  },

  renderStepper: function () {
    var me = this, html = [];
    Ext.each(me.STEPS, function (s, i) {
      if (i > 0) { html.push('<span class="dnsacme-step-sep"></span>'); }
      var cls = "dnsacme-step", isDone = false;
      if (i === me.step) { cls += " active"; } else if (i < me.progressStep) { cls += " done"; isDone = true; }
      if (me.canOpenStep(i)) { cls += " reachable"; }
      // Completed steps recede: a check glyph instead of the number keeps them
      // quiet next to the active step (the single strong accent).
      var glyph = isDone ? '<span class="dnsacme-step-check">&#10003;</span>' : (i + 1);
      html.push('<span class="' + cls + '" data-idx="' + i + '"><span class="dnsacme-step-num">' + glyph + '</span>' + s.text + '</span>');
    });
    if (me.stepper.rendered) { me.stepper.getEl().dom.innerHTML = '<div class="dnsacme-stepper-inner">' + html.join("") + '</div>'; }
  },

  showStep: function (i) {
    var me = this;
    if (i < 0 || i > 3) { return; }
    me.step = i;
    me.cards.getLayout().setActiveItem(me.cardItems[i]);
    me.renderStepper();
    me.syncBar();
    if (i === 3) { me.startLogs(); me.fitLogHeight.defer(1, me); } else { me.stopLogs(); }
  },

  syncBar: function () {
    var me = this, i = me.step;
    if (me.deployedMode) {
      me.prevBtn.hide();
      me.nextBtn.hide();
      me.testBtn.hide();
      me.applyBtn.hide();
      me.reconfigBtn.show();
      return;
    }
    me.prevBtn.setVisible(i > 0);
    me.nextBtn.setVisible(i < 3);
    me.testBtn.setVisible(i === 3);
    me.applyBtn.setVisible(i === 3);
    me.reconfigBtn.hide();
  },

  next: function () {
    var me = this;
    if (!me.validateStep(me.step)) { me.setStatus(SYNO.SDS.DNSACME.t("status.fixFields")); return; }
    var target = me.step + 1;
    me.save(function () {
      if (target > me.progressStep) { me.progressStep = target; }
      me.showStep(target);
    }, me, { refresh: false });
  },

  prev: function () { this.showStep(this.step - 1); },

  reconfigure: function () {
    var me = this;
    me.setStatus(SYNO.SDS.DNSACME.t("status.openingConfiguration"));
    me.reconfigBtn.setDisabled(true);
    SYNO.SDS.DNSACME.request("reconfigure", "POST", {}, function (ok, data) {
      if (me._closed) { return; }
      if (!ok) {
        // DSM can report HTTP 0 after a CGI mutation has already committed.
        // Re-read authoritative state before presenting a transport failure.
        SYNO.SDS.DNSACME.request("config", "GET", null, function (reloadOk, reloadData) {
          if (me._closed) { return; }
          me.reconfigBtn.setDisabled(false);
          if (reloadOk && reloadData.config && reloadData.config.reconfiguring) {
            me.enterReconfigureView(reloadData.config);
            return;
          }
          me.setStatus(SYNO.SDS.DNSACME.t("status.reconfigureFailed", { error: data }), true);
        }, me);
        return;
      }
      me.reconfigBtn.setDisabled(false);
      me.enterReconfigureView(data.config);
    }, me);
  },

  enterReconfigureView: function (cfg) {
    this.forceWizard = true;
    this.deployedMode = false;
    this.cfg = cfg;
    this.setActionsBusy(false);
    if (this.stepper) {
      this.stepper.show();
      this.mainPanel.doLayout();
    }
    this.showStep(0);
    this.setStatus(SYNO.SDS.DNSACME.t("status.ready"));
  },

  validateStep: function (idx) {
    var me = this;
    var form = me.stepForms[idx];
    if (!form) { return true; }
    var ok = true;
    me.eachContainerField(form, function (f) {
      f.dnsacmeValidated = true;
      if (f.validate && f.validate() === false) { ok = false; }
    });
    // ExtJS validates hidden fields too, so a failure inside the collapsed
    // advanced panel would otherwise refuse Next with no visible red field.
    // Expand the panel so the invalid control (and its error icon) is on screen.
    if (!ok && me.advPanel && me.advCollapsed && form === me.stepForms[2]) {
      var advInvalid = false;
      me.eachContainerField(me.advPanel, function (f) {
        if (f.isValid && f.isValid(true) === false) { advInvalid = true; }
      });
      if (advInvalid) { me.setAdvancedCollapsed(false); }
    }
    return ok;
  },

  liveValidateField: function (field) {
    if (!field || !field.on || field.dnsacmeLiveValidate) { return field; }
    field.dnsacmeLiveValidate = true;
    field.enableKeyEvents = true;
    var task = new Ext.util.DelayedTask(function () {
      if (field.rendered && field.validate && (field.dnsacmeValidated || field.isValid() === false)) {
        field.dnsacmeValidated = true;
        field.validate();
      }
    });
    var schedule = function () { task.delay(120); };
    // DSM's ExtJS 3 fields do not emit one consistent input event across text,
    // password, number, paste, and combo controls. Listen at both component and
    // DOM levels, but debounce the validator to avoid layout churn per keypress.
    field.on("keyup", schedule);
    field.on("change", schedule);
    field.on("select", schedule);
    field.on("afterrender", function () {
      var el = field.el || (field.getEl && field.getEl());
      if (!el || !el.on) { return; }
      el.on("keyup", schedule);
      el.on("input", schedule);
      el.on("paste", schedule);
    }, this, { single: true });
    return field;
  },

  // Card header: a step title with an optional muted subtitle, rendered above
  // the fields in the centered, frame-free content area.
  cardHead: function (title, subtitle) {
    var html = '<div class="dnsacme-card-title">' + Ext.util.Format.htmlEncode(title) + '</div>';
    if (subtitle) {
      html += '<div class="dnsacme-card-sub">' + Ext.util.Format.htmlEncode(subtitle) + '</div>';
    }
    return new Ext.BoxComponent({ autoEl: { tag: "div", cls: "dnsacme-card-head", html: html } });
  },

  formPanel: function (id, items, cfg) {
    cfg = cfg || {};
    var formInner = new Ext.Panel({
      border: false,
      layout: "form",
      // The wider default keeps English labels such as "Certificate description"
      // on one line without changing the compact DSM form geometry.
      labelWidth: cfg.labelWidth || 160,
      // Right-aligned labels seat every colon at the label-column edge, so the
      // gap to the input is constant regardless of a label's character count
      // (left alignment left 2-char and 4-char labels with ragged gaps).
      labelAlign: cfg.labelAlign || "right",
      cls: cfg.cls || "",
      bodyStyle: "background:transparent;",
      defaults: Ext.apply({ msgTarget: "side" }, cfg.defaults || {}),
      items: items
    });
    var card = new Ext.Panel({
      border: false,
      layout: "anchor",
      defaults: { anchor: "100%" },
      cls: "dnsacme-content dnsacme-content-form dnsacme-card",
      bodyStyle: "background:transparent;padding:0;",
      items: cfg.title ? [this.cardHead(cfg.title, cfg.subtitle), formInner] : [formInner]
    });
    var form = new Ext.form.FormPanel({
      id: "dnsacme-card-" + id,
      border: false,
      // Anchor only the width. A fit layout also forces the child card's height
      // to the viewport, so expanded advanced fields overflow inside that fixed
      // card and the outer autoScroll container never sees a taller child.
      layout: "anchor",
      defaults: { anchor: "100%" },
      autoScroll: true,
      bodyStyle: "padding:24px 24px 22px 24px;background:transparent;",
      items: [card]
    });
    form.dnsacmeInner = formInner;
    return form;
  },

  contentPanel: function (id, items, cfg) {
    cfg = cfg || {};
    var cardItems = cfg.title ? [this.cardHead(cfg.title, cfg.subtitle)].concat(items) : items;
    // The card is a centered column (.dnsacme-content = max-width 880 + margin
    // auto), shared with the stepper so both align and stay centered as the
    // window grows. The log fills the column (shrinking on narrow windows).
    var card = new Ext.Panel({
      border: false,
      layout: "anchor",
      defaults: { anchor: "100%" },
      cls: "dnsacme-content dnsacme-card",
      bodyStyle: "background:transparent;padding:0;",
      items: cardItems
    });
    return new Ext.Panel({
      id: "dnsacme-card-" + id,
      border: false,
      layout: "fit",
      autoScroll: false,
      bodyStyle: "padding:24px 24px 22px 24px;background:transparent;",
      items: [card]
    });
  },

  logArea: function (height) {
    // A plain <pre> we own end-to-end: exactly one scrollable element (no
    // SYNO.ux TextArea wrapper), so no double scrollbar and native trackpad
    // horizontal scroll. No fixed width: the parent vbox stretch layout sizes it
    // to fill the content area, so it adapts to the window width.
    return new Ext.BoxComponent({
      autoEl: {
        tag: "pre",
        cls: "dnsacme-log",
        style: "height:" + height + "px;"
      }
    });
  },

  // fitLogHeight sizes the visible log <pre> to fill the remaining height of the
  // card region so the pre's own scrollbar owns the overflow. The card region
  // does not scroll (autoScroll:false), so a fixed pre height overflowed the
  // region and the bbar clipped the last line on shorter windows. Only the height
  // is touched, leaving the centered-column width/margin CSS untouched.
  fitLogHeight: function () {
    var me = this;
    var area = me.visibleLogArea();
    if (!area || !area.rendered || !area.el || !me.cards || !me.cards.el) { return; }
    var pre = area.el.dom;
    var regionBottom = me.cards.el.dom.getBoundingClientRect().bottom;
    var preTop = pre.getBoundingClientRect().top;
    // Matches the contentPanel bodyStyle bottom padding (24px 24px 22px 24px).
    var h = Math.floor(regionBottom - preTop - 22);
    if (h < 160) { h = 160; }
    var atBottom = pre.scrollHeight - pre.scrollTop - pre.clientHeight < 24;
    pre.style.height = h + "px";
    if (atBottom) { pre.scrollTop = pre.scrollHeight; }
  },

  visibleLogArea: function () {
    return this.deployedMode ? this.deployedLogsArea : (this.step === 3 ? this.logsArea : null);
  },

  buildCertificate: function () {
    var me = this;
    me.fDomains = new SYNO.ux.TextField({
      fieldLabel: SYNO.SDS.DNSACME.t("field.domain"), width: 380, allowBlank: false,
      emptyText: SYNO.SDS.DNSACME.t("placeholder.domain"), validator: me.validateDomains
    });
    me.liveValidateField(me.fDomains);
    me.fEmail = new SYNO.ux.TextField({
      fieldLabel: SYNO.SDS.DNSACME.t("field.email"), width: 380, allowBlank: false, vtype: "email", emptyText: "you@example.com"
    });
    me.liveValidateField(me.fEmail);
    me.fKeyType = SYNO.SDS.DNSACME.combo({ fieldLabel: SYNO.SDS.DNSACME.t("field.keyType"), width: 380 }, [
      ["rsa4096", "RSA 4096"], ["rsa2048", "RSA 2048"]
    ]);
    me.fCa = SYNO.SDS.DNSACME.combo({ fieldLabel: SYNO.SDS.DNSACME.t("field.issuer"), width: 380 }, [
      ["letsencrypt", "Let's Encrypt"], ["zerossl", "ZeroSSL"]
    ]);
    var form = me.formPanel("certificate", [me.fDomains, me.fEmail, me.fKeyType, me.fCa], {
      title: SYNO.SDS.DNSACME.t("title.certificate"), subtitle: SYNO.SDS.DNSACME.t("subtitle.certificate")
    });
    me.stepForms[0] = form;
    return form;
  },

  validateDomains: function (value) {
    var lines = (value || "").split(/\r?\n|,/), count = 0;
    var re = /^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    for (var i = 0; i < lines.length; i++) {
      var d = Ext.util.Format.trim(lines[i]);
      if (!d) { continue; }
      count++;
      if (count > 1) { return SYNO.SDS.DNSACME.t("validation.singleDomain"); }
      if (!re.test(d)) { return SYNO.SDS.DNSACME.t("validation.invalidDomain", { domain: d }); }
    }
    return count === 1 ? true : SYNO.SDS.DNSACME.t("validation.domainRequired");
  },

  buildDns: function () {
    var me = this;
    me.fProvider = SYNO.SDS.DNSACME.combo({ fieldLabel: SYNO.SDS.DNSACME.t("field.provider"), width: 380 }, []);
    me.fProvider.on("select", me.renderProviderFields, me);
    me.pDns = me.formPanel("dns", [me.fProvider], {
      cls: "dnsacme-dns-form", labelWidth: 160,
      title: SYNO.SDS.DNSACME.t("title.dns"), subtitle: SYNO.SDS.DNSACME.t("subtitle.dns")
    });
    me.stepForms[1] = me.pDns;
    return me.pDns;
  },

  buildSynology: function () {
    var me = this;
    me.fAccount = new SYNO.ux.TextField({
      fieldLabel: SYNO.SDS.DNSACME.t("field.dsmAccount"), width: 380, allowBlank: false,
      emptyText: SYNO.SDS.DNSACME.t("placeholder.dsmAccount")
    });
    me.fPassword = new SYNO.ux.TextField({
      fieldLabel: SYNO.SDS.DNSACME.t("field.dsmPassword"), width: 380, inputType: "password", allowBlank: false,
      emptyText: SYNO.SDS.DNSACME.t("placeholder.dsmPassword")
    });
    me.fCertDesc = new SYNO.ux.TextField({ fieldLabel: SYNO.SDS.DNSACME.t("field.certificateDescription"), width: 380, emptyText: "dnsacme" });
    me.liveValidateField(me.fAccount);
    me.liveValidateField(me.fPassword);
    me.fCreate = new SYNO.ux.Checkbox({ boxLabel: SYNO.SDS.DNSACME.t("option.createCertificate"), hideLabel: true, style: "margin-top:8px" });
    me.fAsDefault = new SYNO.ux.Checkbox({ boxLabel: SYNO.SDS.DNSACME.t("option.setDefault"), hideLabel: true });

    me.fHost = new SYNO.ux.TextField({ fieldLabel: SYNO.SDS.DNSACME.t("field.host"), width: 380, allowBlank: false, emptyText: "127.0.0.1" });
    me.liveValidateField(me.fHost);
    me.fScheme = SYNO.SDS.DNSACME.combo({ fieldLabel: SYNO.SDS.DNSACME.t("field.protocol"), width: 160 }, [["https", "HTTPS"], ["http", "HTTP"]]);
    me.fPort = new SYNO.ux.NumberField({ fieldLabel: SYNO.SDS.DNSACME.t("field.port"), width: 120, minValue: 1, maxValue: 65535, allowDecimals: false, allowBlank: false });
    me.liveValidateField(me.fPort);
    me.advHintVisible = false;
    me.advToggle = new Ext.BoxComponent({
      autoEl: { tag: "div", cls: "dnsacme-adv-toggle", html: '<span class="dnsacme-adv-arrow">▸</span>' + SYNO.SDS.DNSACME.t("advanced.settings") },
      listeners: {
        afterrender: function () {
          me.advToggle.getEl().on("click", function () { me.setAdvancedCollapsed(!me.advCollapsed); });
        },
        scope: me,
        single: true
      }
    });
    me.advPanel = new Ext.Panel({
      border: false, hidden: true, hideLabel: true, cls: "dnsacme-adv-panel", layout: "form", labelWidth: 160, labelAlign: "right",
      bodyStyle: "padding:0", defaults: { msgTarget: "side" },
      items: [me.fHost, me.fScheme, me.fPort],
      listeners: {
        afterrender: function (panel) {
          me.advHintEl = panel.body.insertFirst({
            tag: "div",
            cls: "dnsacme-adv-hint",
            html: SYNO.SDS.DNSACME.t("hint.detectionFailed")
          });
          me.advHintEl.setDisplayed(me.advHintVisible);
        },
        scope: me,
        single: true
      }
    });
    me.advCollapsed = true;

    var form = me.formPanel("synology", [me.fAccount, me.fPassword, me.fCertDesc, me.fCreate, me.fAsDefault, me.advToggle, me.advPanel], {
      title: SYNO.SDS.DNSACME.t("title.autoUpdate"), subtitle: SYNO.SDS.DNSACME.t("subtitle.autoUpdate")
    });
    me.stepForms[2] = form;
    return form;
  },

  setAdvancedCollapsed: function (collapsed) {
    var me = this;
    me.advCollapsed = collapsed;
    if (me.advPanel) {
      if (collapsed) { me.advPanel.hide(); } else { me.advPanel.show(); }
      if (me.advPanel.ownerCt) { me.advPanel.ownerCt.doLayout(); }
    }
    if (me.advToggle && me.advToggle.rendered) {
      me.advToggle.getEl().dom.innerHTML = '<span class="dnsacme-adv-arrow">' + (collapsed ? "▸" : "▾") + '</span>' + SYNO.SDS.DNSACME.t("advanced.settings");
    } else if (me.advToggle && me.advToggle.autoEl) {
      me.advToggle.autoEl.html = '<span class="dnsacme-adv-arrow">' + (collapsed ? "▸" : "▾") + '</span>' + SYNO.SDS.DNSACME.t("advanced.settings");
    }
  },

  setAdvancedHintVisible: function (visible) {
    this.advHintVisible = visible;
    if (this.advHintEl) { this.advHintEl.setDisplayed(visible); }
  },

  buildValidation: function () {
    var me = this;
    me.logsArea = me.logArea(380);
    return me.contentPanel("validation", [me.logsArea], {
      title: SYNO.SDS.DNSACME.t("title.validateApply"), subtitle: SYNO.SDS.DNSACME.t("subtitle.validateApply")
    });
  },

  setActionsBusy: function (busy) {
    this._actionRunning = !!busy;
    if (this.testBtn) { this.testBtn.setDisabled(!!busy); }
    if (this.applyBtn) { this.applyBtn.setDisabled(!!busy); }
  },

  buildDeployed: function () {
    var me = this;
    me.deployedSummary = new Ext.BoxComponent({
      autoEl: { tag: "div", cls: "dnsacme-deployed", html: "" }
    });
    me.deployedLogsArea = me.logArea(380);
    return me.contentPanel("deployed", [me.deployedSummary, me.deployedLogsArea], {});
  },

  enterDeployedView: function (cfg) {
    var me = this;
    me.deployedMode = true;
    me.cards.getLayout().setActiveItem(me.deployedCard);
    if (me.stepper) {
      me.stepper.hide();
      me.mainPanel.doLayout();
    }
    me.updateDeployedSummary(cfg);
    me.syncBar();
    me.startLogs();
    me.fitLogHeight.defer(1, me);
  },

  updateDeployedSummary: function (cfg) {
    var domains = ((cfg.acme && cfg.acme.domains) || []).join(", ");
    var provider = (cfg.dns && cfg.dns.provider) || "";
    var keyType = (cfg.acme && cfg.acme.keyType) || "";
    var ca = (cfg.acme && cfg.acme.ca) || "";
    var lastApply = cfg.lastApply && cfg.lastApply.at ? new Date(cfg.lastApply.at).toLocaleString() : "";
    var keyLabel = keyType === "rsa4096" ? "RSA 4096" : (keyType === "rsa2048" ? "RSA 2048" : keyType);
    var caLabel = ca === "letsencrypt" ? "Let's Encrypt" : (ca === "zerossl" ? "ZeroSSL" : ca);
    var html = [
      '<div class="dnsacme-deployed-title">' + SYNO.SDS.DNSACME.t("title.running") + '</div>',
      '<div class="dnsacme-deployed-grid">',
      '<div class="dnsacme-deployed-line"><span>' + SYNO.SDS.DNSACME.t("summary.domain") + '</span><b>' + Ext.util.Format.htmlEncode(domains || "-") + '</b></div>',
      '<div class="dnsacme-deployed-line"><span>' + SYNO.SDS.DNSACME.t("summary.provider") + '</span><b>' + Ext.util.Format.htmlEncode(provider || "-") + '</b></div>',
      '<div class="dnsacme-deployed-line"><span>' + SYNO.SDS.DNSACME.t("summary.keyType") + '</span><b>' + Ext.util.Format.htmlEncode(keyLabel || "-") + '</b></div>',
      '<div class="dnsacme-deployed-line"><span>' + SYNO.SDS.DNSACME.t("summary.issuer") + '</span><b>' + Ext.util.Format.htmlEncode(caLabel || "-") + '</b></div>',
      '<div class="dnsacme-deployed-line"><span>' + SYNO.SDS.DNSACME.t("summary.lastApplied") + '</span><b>' + Ext.util.Format.htmlEncode(lastApply || "-") + '</b></div>',
      '</div>'
    ].join("");
    if (this.deployedSummary.rendered) { this.deployedSummary.getEl().dom.innerHTML = html; } else { this.deployedSummary.autoEl.html = html; }
  },

  setStatus: function (msg, error) {
    if (this.statusText && this.statusText.setText) {
      this.statusText.setText(msg);
      if (this.statusText.getEl()) {
        this.statusText.getEl()[error ? "addClass" : "removeClass"]("dnsacme-status-error");
      }
    }
  },

  currentProvider: function () {
    var name = this.fProvider.getValue();
    var found = null;
    Ext.each(this.providers, function (p) { if (p.name === name) { found = p; } });
    return found || this.providers[0];
  },

  renderProviderFields: function () {
    var me = this;
    var target = me.pDns.dnsacmeInner || me.pDns;
    Ext.each(me.providerFields, function (f) { target.remove(f, true); });
    me.providerFields = [];
    var prov = me.currentProvider();
    if (prov) {
      Ext.each(prov.fields, function (f) {
        var stored = (me.cfg && me.cfg.dns && me.cfg.dns.config && me.cfg.dns.config[f.key]) || "";
        var opts = {
          fieldLabel: (f.label || f.key) + (f.required ? " *" : ""),
          width: 380, emptyText: f.placeholder || "", value: stored, allowBlank: !f.required,
          labelStyle: "white-space:nowrap;"
        };
        if (f.secret) { opts.inputType = "password"; }
        var field = new SYNO.ux.TextField(opts);
        me.liveValidateField(field);
        field.providerKey = f.key;
        field.providerStoredValue = stored;
        field.on("afterrender", function (cmp) {
          cmp.setValue(cmp.providerStoredValue || "");
          cmp.validate();
        }, me, { single: true });
        me.providerFields.push(field);
        target.add(field);
      });
    }
    if (me.pDns.rendered) {
      target.doLayout();
      me.pDns.doLayout();
      Ext.each(me.providerFields, function (field) {
        field.setValue(field.providerStoredValue || "");
        field.validate();
      });
      // Synology's wrapped TextField can overwrite a value during the layout
      // pass that creates its input element. Reapply once after that pass so
      // redacted and non-secret persisted provider values remain visible.
      Ext.defer(function () {
        Ext.each(me.providerFields, function (field) {
          if (field.rendered) {
            field.setValue(field.providerStoredValue || "");
            field.validate();
          }
        });
      }, 50, me);
    }
  },

  // Mask the whole panel while the very first config load is in flight, so the
  // window opens straight into the correct view (deployed vs wizard) instead of
  // briefly flashing wizard step 1 before applyConfig can switch it.
  maskMain: function (msg) {
    if (this.mainPanel && this.mainPanel.el) { this.mainPanel.el.mask(msg || "", "x-mask-loading"); }
  },

  unmaskMain: function () {
    if (this.mainPanel && this.mainPanel.el) { this.mainPanel.el.unmask(); }
  },

  loadAll: function (opts) {
    var me = this;
    opts = opts || {};
    me.setStatus(SYNO.SDS.DNSACME.t("status.loadingConfig"));
    SYNO.SDS.DNSACME.request("metadata", "GET", null, function (ok, data) {
      if (me._closed) { return; }
      if (!ok) { me.unmaskMain(); me.setStatus(SYNO.SDS.DNSACME.t("status.loadFailed", { error: data })); return; }
      me.providers = data.providers || [];
      var pairs = [];
      Ext.each(me.providers, function (p) { pairs.push([p.name, p.label || p.name]); });
      me.fProvider.getStore().loadData(pairs.map(function (x) { return { v: x[0], t: x[1] }; }));
      SYNO.SDS.DNSACME.request("config", "GET", null, function (ok2, data2) {
        if (me._closed) { return; }
        if (!ok2) { me.unmaskMain(); me.setStatus(SYNO.SDS.DNSACME.t("status.loadFailed", { error: data2 })); return; }
        me.applyConfig(data2.config, data2.testPassed, data2.canRenew, data2.persisted, data2.detected);
        me.unmaskMain();
        me.setStatus(opts.status || SYNO.SDS.DNSACME.t("status.ready"), opts.error);
      }, me);
    }, me);
  },

  applyConfig: function (cfg, testPassed, canRenew, persisted, detected) {
    var me = this;
    me.setActionsBusy(false);
    // cfg is already redacted by the CGI. Mask sentinels are intentionally kept
    // in the controls; mergeSecrets restores their persisted values on save.
    me.cfg = cfg;
    me.forceWizard = !!cfg.reconfiguring;
    me.fDomains.setValue((cfg.acme.domains || []).join("\n"));
    me.fEmail.setValue(cfg.acme.email || "");
    me.fKeyType.setValue(cfg.acme.keyType || "rsa4096");
    me.fCa.setValue(cfg.acme.ca || "letsencrypt");
    me.fProvider.setValue(cfg.dns.provider || (me.providers[0] && me.providers[0].name));
    me.renderProviderFields();

    var scheme = cfg.synology.scheme || "https";
    var host = cfg.synology.host || "127.0.0.1";
    var port = cfg.synology.port || 5001;
    var expandAdvanced = false;
    // Detection seeds only a first-run form. Once a config exists, persisted or
    // manually entered connection values always win over nginx discovery.
    if (!persisted) {
      if (detected && detected.detected) { scheme = detected.scheme; port = detected.port; }
      else { expandAdvanced = true; }
    }
    me.fHost.setValue(host);
    me.fScheme.setValue(scheme);
    me.fPort.setValue(port);
    me.setAdvancedCollapsed(!expandAdvanced);
    me.setAdvancedHintVisible(expandAdvanced);

    me.fAccount.setValue(cfg.synology.account || "");
    me.fPassword.setValue(cfg.synology.password || "");
    me.fCertDesc.setValue(cfg.synology.certificateDesc || "");
    me.fCreate.setValue(!!cfg.synology.create);
    me.fAsDefault.setValue(!!cfg.synology.asDefault);
    me._testPassed = !!testPassed;
    for (var i = 0; i < me.stepForms.length; i++) { me.markStepClean(i); }
    if (canRenew && !me.forceWizard) {
      me.enterDeployedView(cfg);
    } else {
      // Persisted reconfiguration mode may arrive while the deployed card is
      // visible, so explicitly restore the current wizard card as well as the
      // stepper instead of only updating button visibility.
      me.deployedMode = false;
      if (me.stepper) {
        me.stepper.show();
        me.mainPanel.doLayout();
      }
      me.showStep(me.step);
    }
  },

  collectConfig: function () {
    var me = this;
    var dnsConfig = {};
    Ext.each(me.providerFields, function (f) { dnsConfig[f.providerKey] = f.getValue(); });
    var domains = [];
    Ext.each((me.fDomains.getValue() || "").split(/\r?\n|,/), function (d) {
      d = Ext.util.Format.trim(d);
      if (d) { domains.push(d); }
    });
    return {
      acme: { domains: domains, email: Ext.util.Format.trim(me.fEmail.getValue()), keyType: me.fKeyType.getValue(), ca: me.fCa.getValue() },
      dns: { provider: me.fProvider.getValue(), config: dnsConfig },
      synology: {
        scheme: me.fScheme.getValue(), host: Ext.util.Format.trim(me.fHost.getValue()) || "127.0.0.1",
        port: Number(me.fPort.getValue()), account: Ext.util.Format.trim(me.fAccount.getValue()),
        password: me.fPassword.getValue(), certificateDesc: Ext.util.Format.trim(me.fCertDesc.getValue()),
        create: me.fCreate.getValue(), asDefault: me.fAsDefault.getValue()
      },
      // Runtime paths are package-owned and have no editable controls. Preserve
      // the server-provided values instead of synthesizing browser-side paths.
      runtime: (me.cfg && me.cfg.runtime) || {}
    };
  },

  save: function (cb, scope, opts) {
    var me = this;
    opts = opts || {};
    me.setStatus(SYNO.SDS.DNSACME.t("status.saving"));
    SYNO.SDS.DNSACME.request("config", "POST", me.collectConfig(), function (ok, data) {
      if (me._closed) { return; }
      if (!ok) {
        me.setStatus(SYNO.SDS.DNSACME.t("status.saveFailed", { error: data }));
        if (opts.onFail) { opts.onFail(); }
        return;
      }
      me.markStepClean(me.step);
      if (opts.refresh === false) {
        // Step navigation only needs the saved config and optional test state.
        // Avoid a full applyConfig call because rebuilding dynamic fields would
        // disturb focus and dirty tracking before the next card is shown.
        me.cfg = data.config;
        me._testPassed = !!data.testPassed;
      } else {
        me.applyConfig(data.config, data.testPassed, data.canRenew, data.persisted, data.detected);
      }
      me.setStatus(SYNO.SDS.DNSACME.t("status.saved"));
      if (cb) { cb.call(scope || me); }
    }, me);
  },

  requestAction: function (action) {
    var me = this;
    if (me._actionRunning) { return; }
    if (action !== "apply") {
      me.runAction(action);
      return;
    }
    if (!me._testPassed) {
      me.showApplyConfirmation("dialog.applyUntestedTitle", "dialog.applyUntestedBody");
      return;
    }
    var testedAt = me.cfg && me.cfg.lastTest && me.cfg.lastTest.at ? new Date(me.cfg.lastTest.at).getTime() : 0;
    if (testedAt && Date.now() - testedAt < 10 * 60 * 1000) {
      me.showApplyConfirmation("dialog.applyRecentTestTitle", "dialog.applyRecentTestBody");
      return;
    }
    me.runAction("apply");
  },

  showApplyConfirmation: function (titleKey, bodyKey) {
    var me = this;
    me.getMsgBox().show({
      title: SYNO.SDS.DNSACME.t(titleKey),
      msg: Ext.util.Format.htmlEncode(SYNO.SDS.DNSACME.t(bodyKey)),
      buttons: Ext.MessageBox.YESNO,
      icon: Ext.MessageBox.WARNING,
      minWidth: 420,
      maxWidth: 560,
      fn: function (button) {
        if (button === "yes") { me.runAction("apply"); }
      }
    });
  },

  showTestSuccessDialog: function () {
    this.getMsgBox().show({
      title: SYNO.SDS.DNSACME.t("dialog.testSuccessTitle"),
      msg: Ext.util.Format.htmlEncode(SYNO.SDS.DNSACME.t("dialog.testSuccessBody")),
      buttons: Ext.MessageBox.OK,
      icon: Ext.MessageBox.INFO,
      minWidth: 420,
      maxWidth: 560
    });
  },

  runAction: function (action) {
    var me = this;
    me.setActionsBusy(true);
    me.save(function () {
      if (me._closed) { return; }
      var requesting = action === "test-run"
        ? SYNO.SDS.DNSACME.t("status.requestingStaging")
        : SYNO.SDS.DNSACME.t("status.requestingProduction");
      me.setStatus(requesting);
      me.mainPanel.el.mask(requesting, "x-mask-loading");
      SYNO.SDS.DNSACME.request(action, "POST", {}, function (ok, data) {
        if (me._closed) { return; }
        me.mainPanel.el.unmask();
        if (!ok) {
          me.reconcileActionState(action, data);
          return;
        }
        if (action === "apply") { me.forceWizard = false; }
        me.setStatus(action === "test-run"
          ? SYNO.SDS.DNSACME.t("status.stagingComplete")
          : SYNO.SDS.DNSACME.t("status.productionApplied"));
        me.finishAction(action, data);
      }, me);
    }, me, {
      // Skip the field-rebuilding applyConfig here: navigation stays on step 4
      // while the long-running task owns the mask and action buttons.
      refresh: false,
      onFail: function () {
        me.setActionsBusy(false);
      }
    });
  },

  // finishAction settles the wizard after a test-run or apply reported success
  // (directly or via reconcileActionState). A passed test-run records diagnostic
  // state and stays on the final step; Apply was already available independently.
  // DSM's SCGI gateway resets long test-run/apply POSTs and can stall the very
  // next request. Both successful action responses and the status reconciliation
  // response carry a redacted config, so settle locally instead of calling
  // loadAll and leaving the wizard stuck on "loading configuration".
  finishAction: function (action, data) {
    var me = this;
    if (action === "test-run") {
      me.setActionsBusy(false);
      me._testPassed = true;
      if (data && data.config) {
        if (data.config.acme) { me.cfg = data.config; }
        else if (data.config.lastTest) { me.cfg.lastTest = data.config.lastTest; }
      }
      me.loadLogs();
      me.showTestSuccessDialog();
      return;
    }
    me.setActionsBusy(false);
    if (!data || !data.config) {
      me.setStatus(SYNO.SDS.DNSACME.t("status.loadFailed", { error: SYNO.SDS.DNSACME.t("error.invalidResponse") }), true);
      return;
    }
    me.cfg = data.config;
    me.enterDeployedView(data.config);
    me.loadLogs();
  },

  reconcileActionState: function (action, errorText) {
    var me = this;
    // DSM may surface a long-running CGI completion as HTTP 0 even though the Go
    // process finished. Treat persisted operation state as authoritative before
    // displaying a failure, then use the log tail for the actionable reason.
    SYNO.SDS.DNSACME.request("status", "GET", null, function (ok, data) {
      if (me._closed) { return; }
      var completed = ok && (
        (action === "test-run" && data.testPassed) ||
        (action === "apply" && data.canRenew)
      );
      if (completed) {
        if (action === "apply") { me.forceWizard = false; }
        me.setStatus(action === "test-run"
          ? SYNO.SDS.DNSACME.t("status.stagingComplete")
          : SYNO.SDS.DNSACME.t("status.productionApplied"));
        me.finishAction(action, action === "test-run" ? { config: { lastTest: data.lastTest } } : data);
        return;
      }
      SYNO.SDS.DNSACME.request("logs", "GET", null, function (logsOk, logsData) {
        var reason = me.lastFailureLine((logsOk && logsData && logsData.logs) || "", errorText);
        var status = action === "test-run" ? SYNO.SDS.DNSACME.t("dialog.testFailed") : SYNO.SDS.DNSACME.t("dialog.applyFailed");
        me.loadAll({ status: status, error: true });
        me.loadLogs();
        me.showActionFailure(action, reason);
      }, me);
    }, me);
  },

  showActionFailure: function (action, reason) {
    var me = this;
    var title = action === "test-run" ? SYNO.SDS.DNSACME.t("dialog.testFailed") : SYNO.SDS.DNSACME.t("dialog.applyFailed");
    var friendlyMessage = me.friendlyFailureMessage(action, reason);
    // Route through the app window's own message box (SYNO.SDS.AppWindow#getMsgBox)
    // instead of a free-floating Ext.Window. This gives three things the hand-rolled
    // window could not: the mask is scoped to THIS app window only (the DSM desktop
    // and other apps stay usable), it centers on the app window rather than the whole
    // desktop, and it carries DSM's native rounded/shadowed dialog chrome plus the
    // localized OK button. We only supply the icon + title + message as body HTML.
    var body = [
      '<div class="dnsacme-error-dialog">',
      '<div class="dnsacme-error-head">',
      '<div class="dnsacme-error-icon" role="img" aria-label="' + Ext.util.Format.htmlEncode(SYNO.SDS.DNSACME.t("error.label")) + '">!</div>',
      '<div class="dnsacme-error-title">' + Ext.util.Format.htmlEncode(title) + '</div>',
      '</div>',
      '<div class="dnsacme-error-message">' + Ext.util.Format.htmlEncode(friendlyMessage) + '</div>',
      '</div>'
    ].join("");
    me.getMsgBox().show({
      title: title,
      msg: body,
      buttons: Ext.MessageBox.OK,
      icon: "",
      minWidth: 360,
      maxWidth: 460,
      cls: "dnsacme-error-msgbox"
    });
  },

  friendlyFailureMessage: function (action, reason) {
    var text = String(reason || "").toLowerCase();
    if (text.indexOf("dsm login failed") >= 0 || text.indexOf("synology auth failed") >= 0) {
      return SYNO.SDS.DNSACME.t("error.dsmLogin");
    }
    if (text.indexOf("synology dsm import failed") >= 0 || text.indexOf("certificate import failed") >= 0) {
      return SYNO.SDS.DNSACME.t("error.dsmImport");
    }
    if (text.indexOf("ratelimited") >= 0 || text.indexOf("http 429") >= 0) {
      return SYNO.SDS.DNSACME.t("error.caRateLimited");
    }
    if (text.indexOf("incorrect txt record") >= 0 || text.indexOf("secondary validation") >= 0 || text.indexOf("dns problem") >= 0) {
      return SYNO.SDS.DNSACME.t("error.dnsValidation");
    }
    if (text.indexOf("adding temporary record") >= 0 || text.indexOf("dns provider") >= 0 || text.indexOf("accesskey") >= 0 || text.indexOf("api token") >= 0) {
      return SYNO.SDS.DNSACME.t("error.dnsProvider");
    }
    return action === "test-run" ? SYNO.SDS.DNSACME.t("error.testGeneric") : SYNO.SDS.DNSACME.t("error.applyGeneric");
  },

  lastFailureLine: function (logs, fallback) {
    var lines = (logs || "").split(/\r?\n/);
    for (var i = lines.length - 1; i >= 0; i--) {
      var line = Ext.util.Format.trim(lines[i] || "");
      if (!line) { continue; }
      if (line.indexOf(" failed") >= 0 || line.indexOf("failed:") >= 0 || line.indexOf("\u5931\u8d25") >= 0) {
        return line;
      }
    }
    return fallback;
  },

  startLogs: function () {
    var me = this;
    me.stopLogs();
    me.loadLogs();
    me.logsTask = { run: me.loadLogs, scope: me, interval: 2000 };
    Ext.TaskMgr.start(me.logsTask);
  },

  stopLogs: function () {
    if (this.logsTask) { Ext.TaskMgr.stop(this.logsTask); this.logsTask = null; }
  },

  loadLogs: function () {
    var me = this;
    SYNO.SDS.DNSACME.request("logs", "GET", null, function (ok, data) {
      if (me._closed || !ok) { return; }
      // Updating a hidden <pre> gives it clientHeight=0, which makes the tail
      // detector preserve scrollTop=0. Refresh only the visible log so a newly
      // entered view starts pinned to the latest line.
      me.setLogArea(me.visibleLogArea(), data.logs || "");
    }, me);
  },

  setLogArea: function (area, logs) {
    if (!area || !area.rendered || !area.el) { return; }
    logs = logs || "";
    var dom = area.el.dom;
    if (dom.dnsacmeLogs === logs) { return; }
    // Don't wipe a selection the user is making inside this log (they're copying).
    // Skip this refresh; the next tick applies it once the selection is cleared.
    var sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && sel.focusNode &&
        dom.contains(sel.anchorNode) && dom.contains(sel.focusNode)) {
      return;
    }
    // Keep the user's horizontal position; keep following the tail only if
    // already pinned near the bottom.
    var atBottom = dom.scrollHeight - dom.scrollTop - dom.clientHeight < 24;
    var scrollLeft = dom.scrollLeft;
    dom.innerHTML = this.renderLogLines(logs);
    dom.dnsacmeLogs = logs;
    dom.scrollLeft = scrollLeft;
    if (atBottom) { dom.scrollTop = dom.scrollHeight; }
  },

  renderLogLines: function (logs) {
    var lines = String(logs || "").split(/\r?\n/);
    var html = [];
    Ext.each(lines, function (line) {
      var cls = "";
      if (/(^|\s)(ERRO|ERROR)(\s|$)/.test(line)) {
        cls = "dnsacme-log-error";
      } else if (/(^|\s)WARN(\s|$)/.test(line)) {
        cls = "dnsacme-log-warn";
      }
      var encoded = Ext.util.Format.htmlEncode(line);
      html.push(cls ? '<span class="' + cls + '">' + encoded + '</span>' : encoded);
    });
    return html.join("\n");
  }
});
