//go:build synology

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSynologyUIAuthenticationDialog(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the authentication dialog behavior test")
	}
	script := `
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const definitions = {}, sent = [];
function Field(config) { Object.assign(this, config); this.value = config.value || ''; }
Field.prototype.getValue = function () { return this.value; };
Field.prototype.setValue = function (v) { this.value = v; };
Field.prototype.markInvalid = function (msg) { this.error = msg; };
function Button(config) { Object.assign(this, config); }
Button.prototype.setDisabled = function (v) { this.disabled = v; };
function Window(config) { Object.assign(this, config); }
Window.prototype.show = function () {};
Window.prototype.close = function () { this.listeners.close(); };
const context = {
  SYNO: { SDS: { DNSACME: {} }, ux: { TextField: Field, Button } },
  document: { documentElement: { getAttribute: () => 'en' } }, navigator: { language: 'en' },
  Ext: { ns() {}, define: (name, definition) => { definitions[name] = definition; },
    Window, decode: JSON.parse, apply: Object.assign,
    util: { Format: { htmlEncode: (s) => s, trim: (s) => s.trim() } },
    each: (items, fn) => items.forEach(fn),
    Ajax: { request: (options) => sent.push({ options, body: JSON.parse(JSON.stringify(options.jsonData)) }) }
  }
};
vm.runInNewContext(fs.readFileSync('synology/spk/ui/DNSACME.js', 'utf8'), context);
const proto = definitions['SYNO.SDS.DNSACME.MainWindow'];
const me = Object.assign({}, proto, { configEditToken: 'saved-config', setStatus() {}, refreshAuthStatus() {} });
me.showDSMAuthDialog();
let dialog = me._authDialog, otp = dialog.items[1], submit = dialog.buttons[0];
otp.setValue('invalid'); submit.handler();
assert.equal(sent.length, 0, 'invalid OTP reached the network');
otp.setValue('123456'); submit.handler();
assert.equal(sent.length, 1);
assert.equal(sent[0].body.otp, '123456');
assert.equal(sent[0].body.editToken, 'saved-config');
assert.equal(sent[0].options.method, 'POST');
assert(!sent[0].options.url.includes('123456'));
assert.equal(otp.getValue(), '', 'OTP remained in the input');
submit.handler(); assert.equal(sent.length, 1, 'duplicate sign-in allowed');
sent[0].options.failure({ responseText: JSON.stringify({success:false,error:'fresh OTP required'}), status:400 });
assert.equal(me._authRunning, false);
assert.equal(otp.getValue(), '');
assert.equal(submit.disabled, false);
otp.setValue('654321'); submit.handler();
sent[1].options.success({ responseText: JSON.stringify({success:true,data:{status:'ready'}}) });
assert.equal(me._authDialog, null);
me.showDSMAuthDialog(); dialog = me._authDialog;
dialog.items[1].setValue(''); dialog.buttons[0].handler();
assert.equal(sent[2].body.otp, '', 'non-2FA sign-in must allow an empty code');
me._auth = {status:'reauth_required'};
assert(me.authStatusText().includes('fresh code'));
me._auth = {status:'ready',deploymentPending:true};
assert(me.authStatusText().includes('waiting to be installed'));
me._auth = {status:'ready',trustedDevice:true};
assert.equal(me.authStatusText(), 'Trusted device ready');
`
	path := filepath.Join(t.TempDir(), "auth-ui.cjs")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(node, path).CombinedOutput(); err != nil {
		t.Fatalf("authentication dialog: %v\n%s", err, output)
	}
}
