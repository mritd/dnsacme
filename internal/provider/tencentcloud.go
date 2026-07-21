//go:build tencentcloud || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/tencentcloud"
)

// newTencentCloud validates Tencent Cloud credentials and constructs its libdns provider.
func newTencentCloud(config map[string]string) (certmagic.DNSProvider, error) {
	secretID, ok := config[TencentCloudAccessKeyID]
	if !ok {
		return nil, errors.New("failed to get TencentCloud AccessKeyID")
	}
	secretKey, ok := config[TencentCloudAccessKeySecret]
	if !ok {
		return nil, errors.New("failed to get TencentCloud AccessKeySecret")
	}
	return &tencentcloud.Provider{SecretId: secretID, SecretKey: secretKey}, nil
}

// init registers Tencent Cloud DNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: TencentCloud, Label: "Tencent Cloud DNS", Fields: []Field{
		{Key: TencentCloudAccessKeyID, Label: "Secret ID", Required: true, Placeholder: "AKID..."},
		{Key: TencentCloudAccessKeySecret, Label: "Secret Key", Secret: true, Required: true},
	}}, newTencentCloud)
}
