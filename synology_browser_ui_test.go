//go:build synology

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserUIBootstrapsNativeAndPackageTokens(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("node unavailable")
	}
	script := `
const fs=require('fs'),vm=require('vm'),assert=require('assert');const requests=[];
const context={document:{documentElement:{getAttribute:()=> 'en'}},navigator:{language:'en'},SYNO:{SDS:{DNSACME:{}}},Ext:{ns(){},define(){},Ajax:{request(o){requests.push(o)}}}};
vm.runInNewContext(fs.readFileSync('synology/spk/ui/DNSACME.js','utf8'),context);
context.SYNO.SDS.DNSACME.request('config','POST',{editToken:'version'},()=>{});
assert(requests[0].url.includes('SYNO.API.Auth'));
requests[0].success({responseText:JSON.stringify({success:true,data:{synotoken:'native-token'}})});
assert(requests[1].url.endsWith('?action=csrf'));
assert.equal(requests[1].headers['X-SYNO-TOKEN'],'native-token');
requests[1].success({responseText:JSON.stringify({success:true,data:{csrfToken:'package-token'}})});
assert.equal(requests[2].headers['X-SYNO-TOKEN'],'native-token');
assert.equal(requests[2].headers['X-DNSACME-CSRF'],'package-token');
assert.equal(requests[2].jsonData.editToken,'version');
`
	// The production wrapper uses DSM's JSON decoder.
	script = strings.Replace(script, "Ajax:{request", "decode:JSON.parse,Ajax:{request", 1)
	p := filepath.Join(t.TempDir(), "browser.cjs")
	if e = os.WriteFile(p, []byte(script), 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command(node, p).CombinedOutput(); e != nil {
		t.Fatalf("browser bootstrap: %v\n%s", e, out)
	}
}
