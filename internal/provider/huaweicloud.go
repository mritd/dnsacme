//go:build huaweicloud || !slim

package provider

import (
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/huaweicloud"
)

// newHuaweiCloud validates Huawei Cloud credentials and constructs its libdns provider.
func newHuaweiCloud(config map[string]string) (certmagic.DNSProvider, error) {
	accessKeyID, ok := config[HuaweiCloudAccessKeyID]
	if !ok {
		return nil, errors.New("failed to get HuaweiCloud AccessKeyID")
	}
	accessKeySecret, ok := config[HuaweiCloudAccessKeySecret]
	if !ok {
		return nil, errors.New("failed to get HuaweiCloud AccessKeySecret")
	}
	return &huaweicloud.Provider{
		AccessKeyId: accessKeyID, SecretAccessKey: accessKeySecret, RegionId: config[HuaweiCloudRegionID],
	}, nil
}

// init registers Huawei Cloud DNS when its build constraint is satisfied.
func init() {
	register(Definition{Name: HuaweiCloud, Label: "Huawei Cloud DNS", Fields: []Field{
		{Key: HuaweiCloudAccessKeyID, Label: "AccessKey ID", Required: true, Placeholder: "access key id"},
		{Key: HuaweiCloudAccessKeySecret, Label: "Secret AccessKey", Secret: true, Required: true},
		{Key: HuaweiCloudRegionID, Label: "Region ID", Placeholder: "cn-south-1"},
	}}, newHuaweiCloud)
}
