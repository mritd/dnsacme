//go:build alidns || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
)

// newAliDNS validates AliDNS credentials and constructs its libdns provider.
func newAliDNS(config map[string]string) (certmagic.DNSProvider, error) {
	accessKeyID, ok := config[AliDNSAccessKeyID]
	if !ok {
		return nil, errors.New("failed to get AliDNS AccessKeyID")
	}
	accessKeySecret, ok := config[AliDNSAccessKeySecret]
	if !ok {
		return nil, errors.New("failed to get AliDNS AccessKeySecret")
	}
	return &alidns.Provider{CredentialInfo: alidns.CredentialInfo{
		AccessKeyID: accessKeyID, AccessKeySecret: accessKeySecret, RegionID: config[AliDNSRegionID],
	}}, nil
}

// init registers AliDNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: AliDNS, Label: "AliDNS", Fields: []Field{
		{Key: AliDNSAccessKeyID, Label: "AccessKey ID", Required: true, Placeholder: "LTAI..."},
		{Key: AliDNSAccessKeySecret, Label: "AccessKey Secret", Secret: true, Required: true},
		{Key: AliDNSRegionID, Label: "Region ID", Placeholder: "cn-hangzhou"},
	}}, newAliDNS)
}
