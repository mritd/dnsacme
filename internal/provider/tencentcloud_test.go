//go:build tencentcloud || !slim

package provider

import (
	"testing"

	"github.com/libdns/tencentcloud"
)

func TestNewTencentCloud_MapsCredentials(t *testing.T) {
	got, err := New(TencentCloud, map[string]string{
		TencentCloudAccessKeyID: "id", TencentCloudAccessKeySecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := got.(*tencentcloud.Provider)
	if !ok || provider.SecretId != "id" || provider.SecretKey != "secret" {
		t.Fatalf("unexpected provider: %#v", got)
	}
}

func TestNewTencentCloud_RequiresBothCredentials(t *testing.T) {
	tests := []struct {
		config map[string]string
		want   string
	}{
		{config: map[string]string{}, want: "failed to get TencentCloud AccessKeyID"},
		{config: map[string]string{TencentCloudAccessKeyID: "id"}, want: "failed to get TencentCloud AccessKeySecret"},
	}
	for _, test := range tests {
		_, err := New(TencentCloud, test.config)
		if err == nil || err.Error() != test.want {
			t.Fatalf("New error = %v, want %q", err, test.want)
		}
	}
}
