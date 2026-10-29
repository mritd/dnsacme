//go:build synology

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSynologyUIAuthenticationConnectionPanel(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the authentication panel behavior test")
	}
	script := `
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const definitions = {}, sent = [];
function Collection(items) { this.list = items || []; }
Collection.prototype.each = function (fn) { this.list.forEach(fn); };
Collection.prototype.itemAt = function (i) { return this.list[i]; };
function Component(config) {
  Object.assign(this, config); this.hidden = !!this.hidden;
  if (config.items) {
    this.items = new Collection(config.items);
    this.items.each((item) => { if (item && typeof item === 'object') item.ownerCt = this; });
  }
}
Component.prototype.show = function () { this.hidden = false; };
Component.prototype.hide = function () { this.hidden = true; };
Component.prototype.isVisible = function () { return !this.hidden; };
Component.prototype.setVisible = function (v) { this.hidden = !v; };
Component.prototype.setDisabled = function (v) { this.disabled = v; };
Component.prototype.focus = function () { this.focused = true; };
Component.prototype.doLayout = function () {};
Component.prototype.on = function () {};
Component.prototype.getLayout = function () {
  if (!this.layoutObject) this.layoutObject = {setActiveItem(item) { this.activeItem = item; }};
  return this.layoutObject;
};
function Field(config) { Component.call(this, config); this.value = config.value || ''; }
Field.prototype = Object.create(Component.prototype);
Field.prototype.getValue = function () { return this.value; };
Field.prototype.setValue = function (v) { this.value = v; };
Field.prototype.markInvalid = function (msg) { this.error = msg; };
Field.prototype.clearInvalid = function () { this.error = ''; };
Field.prototype.validate = function () { return !this.error; };
Field.prototype.getEl = function () { return {set: (attrs) => { this.attrs = attrs; }}; };
function Toolbar(config) { Component.call(this, config); }
Toolbar.TextItem = function (text) { this.text = text; };
const encode = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const context = {
  SYNO: { SDS: { DNSACME: {} }, ux: { TextField: Field, NumberField: Field, Checkbox: Field, Button: Component } },
  document: { documentElement: { getAttribute: () => 'en' } }, navigator: { language: 'en' },
  Ext: { ns() {}, define: (name, definition) => { definitions[name] = definition; },
    Panel: Component, BoxComponent: Component, Toolbar, form: {FormPanel: Component},
    decode: JSON.parse, apply: Object.assign,
    util: { Format: { htmlEncode: encode, trim: (s) => s.trim() } },
    each: (items, fn) => items.forEach(fn),
    Ajax: { request: (options) => sent.push({ options, body: JSON.parse(JSON.stringify(options.jsonData)) }) }
  }
};
vm.runInNewContext(fs.readFileSync('synology/spk/ui/DNSACME.js', 'utf8'), context);
context.SYNO.SDS.DNSACME.combo = (config) => new Field(config);
const proto = definitions['SYNO.SDS.DNSACME.MainWindow'];
let saves = 0, refreshes = 0;
const fit = function () {}; fit.defer = function () {};
const me = Object.assign({}, proto, {
  configEditToken: 'saved-config', _closed: false,
  setStatus(msg) { this.statusMessage = msg; }, refreshAuthStatus() { refreshes++; },
  liveValidateField() {}, reflowWindowLayout() {}, stopLogs() {}, startLogs() {}, fitLogHeight: fit,
  buildCertificate() { return new Component({items: []}); }, buildDns() { return new Component({items: []}); },
  buildValidation() { return new Component({items: []}); }, buildStepper() { this.stepper = new Component({}); return this.stepper; },
  save(fn, scope) { saves++; fn.call(scope); }
});
me.buildUI();
function contains(root, target) {
  return root === target || !!(root && root.items && root.items.list.some((item) => contains(item, target)));
}
assert(contains(me.cardItems[2], me.authBtn), 'sign-in is missing from the account/password step');
[0, 1, 3].forEach((step) => assert(!contains(me.cardItems[step], me.authBtn), 'sign-in leaked into another step'));
assert(!contains(me.mainPanel.bbar, me.authBtn), 'sign-in is still a wizard footer action');
assert(contains(me.deployedCard, me.connectionBtn), 'running view has no connection-management entry');
assert(!contains(me.deployedCard, me.authBtn), 'running view must enter connection management first');
me._auth = {status:'ready',trustedDevice:true,deviceName:'Existing device'};
me.showDSMAuthPanel();
const view = me.wizardAuth;
view.otp.listeners.afterrender(view.otp);
assert.equal(view.otp.attrs.autocomplete, 'one-time-code');
assert.equal(view.otp.attrs.inputmode, 'numeric');
assert.equal(view.device.getValue(), 'Existing device');
view.otp.setValue('123456'); view.cancel.handler();
assert(view.panel.hidden); assert.equal(view.otp.getValue(), ''); assert.equal(sent.length, 0);
me.showDSMAuthPanel(); view.otp.setValue('654321'); view.close.handler();
assert(view.panel.hidden); assert.equal(view.otp.getValue(), ''); assert.equal(sent.length, 0);
me.showDSMAuthPanel();
view.otp.setValue('123456');
view.otp.isDirty = () => true;
me.step = 2;
assert.equal(me.isCurrentStepDirty(), false, 'transient OTP changed wizard dirty state');
view.otp.markInvalid('invalid OTP');
assert.equal(me.validateStep(2), true, 'transient input blocked normal wizard validation');
view.otp.clearInvalid();
me.showStep(3);
assert(view.panel.hidden); assert.equal(view.otp.getValue(), '', 'navigation retained an OTP');
me.step = 2; me.authenticateDSM();
assert.equal(saves, 1, 'wizard sign-in did not save edited account settings');
view.otp.setValue('invalid'); view.submit.handler();
assert.equal(sent.length, 0, 'invalid OTP reached the network');
view.otp.setValue('123456'); view.submit.handler();
assert.equal(sent.length, 1); assert.equal(sent[0].body.otp, '123456');
assert.equal(sent[0].body.editToken, 'saved-config'); assert.equal(sent[0].options.method, 'POST');
assert(!sent[0].options.url.includes('123456'));
assert.equal(view.otp.getValue(), '', 'OTP remained in the input');
assert.equal(view.otp.disabled, true);
view.submit.handler(); assert.equal(sent.length, 1, 'duplicate sign-in allowed');
sent[0].options.failure({responseText: JSON.stringify({success:false,error:'fresh code required <script>'}),status:400});
assert.equal(me._authRunning, false); assert.equal(view.submit.disabled, false); assert.equal(view.otp.disabled, false);
assert(!view.panel.hidden, 'failed sign-in hid its recovery controls');
assert(view.status.autoEl.html.includes('&lt;script&gt;'), 'failure feedback is not escaped');
assert(view.status.autoEl.html.includes('role="alert"'));
view.otp.setValue('654321'); view.submit.handler();
sent[1].options.success({responseText: JSON.stringify({success:true,data:{status:'ready',trustedDevice:true}})});
assert(view.panel.hidden); assert.equal(view.otp.getValue(), ''); assert.equal(refreshes, 2);
me.cfg = {acme:{domains:['nas.example.com']},lastApply:{success:true}};
me.enterDeployedView(me.cfg);
const savedConfig = JSON.stringify(me.cfg), savedToken = me.configEditToken;
me.connectionBtn.handler.call(me);
assert.equal(saves, 1, 'opening connection management saved/reconfigured the active certificate');
assert.equal(me.cards.getLayout().activeItem, me.connectionCard);
assert(me.reconfigBtn.hidden); assert(me.deployedMode);
const active = me.connectionAuth;
active.otp.setValue('123456'); active.close.handler();
assert.equal(me.cards.getLayout().activeItem, me.deployedCard);
assert.equal(active.otp.getValue(), ''); assert.equal(sent.length, 2);
me.connectionBtn.handler.call(me);
active.otp.setValue(''); active.submit.handler();
assert.equal(sent[2].body.otp, '', 'trusted-device verification must allow an empty code');
// Closing while a request is in flight is always available. A late result must
// update status without reopening or navigating away from the running view.
active.cancel.handler();
assert.equal(me.cards.getLayout().activeItem, me.deployedCard);
sent[2].options.success({responseText: JSON.stringify({success:true,data:{status:'ready',trustedDevice:true}})});
assert(active.panel.hidden); assert.equal(me.cards.getLayout().activeItem, me.deployedCard);
assert.equal(JSON.stringify(me.cfg), savedConfig); assert.equal(me.configEditToken, savedToken);
assert.equal(saves, 1);
me.connectionBtn.handler.call(me);
active.otp.setValue('123456');
active.otp.listeners.specialkey(active.otp, {getKey:()=>27, ENTER:13, ESC:27});
assert.equal(active.otp.getValue(), ''); assert(active.panel.hidden);
me._auth = {status:'reauth_required'}; assert(me.authStatusText().includes('fresh code'));
me._auth = {status:'ready',deploymentPending:true}; assert(me.authStatusText().includes('waiting to be installed'));
me._auth = {status:'ready',trustedDevice:true}; assert.equal(me.authStatusText(), 'Trusted device ready');
`
	path := filepath.Join(t.TempDir(), "auth-ui.cjs")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, path).CombinedOutput(); err != nil {
		t.Fatalf("authentication panel: %v\n%s", err, output)
	}
}
