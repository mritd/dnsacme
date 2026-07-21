//go:build huaweicloud || !slim

package provider

import (
	"testing"

	"github.com/libdns/huaweicloud"
)

func TestNewHuaweiCloud_MapsCredentials(t *testing.T) {
	got, err := New(HuaweiCloud, map[string]string{
		HuaweiCloudAccessKeyID: "id", HuaweiCloudAccessKeySecret: "secret", HuaweiCloudRegionID: "cn-south-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*huaweicloud.Provider)
	if !ok || provider.AccessKeyId != "id" || provider.SecretAccessKey != "secret" || provider.RegionId != "cn-south-1" {
		t.Fatalf("unexpected provider: %#v", got)
	}
}

func TestNewHuaweiCloud_RequiresBothCredentials(t *testing.T) {
	tests := []struct {
		config map[string]string
		want   string
	}{
		{config: map[string]string{}, want: "failed to get HuaweiCloud AccessKeyID"},
		{config: map[string]string{HuaweiCloudAccessKeyID: "id"}, want: "failed to get HuaweiCloud AccessKeySecret"},
	}
	for _, test := range tests {
		_, err := New(HuaweiCloud, test.config)
		if err == nil || err.Error() != test.want {
			t.Fatalf("New error = %v, want %q", err, test.want)
		}
	}
}
