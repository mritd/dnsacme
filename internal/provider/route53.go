//go:build route53 || !slim

package provider

import (
	"cmp"
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/route53"
)

// route53DefaultRegion is used for request signing when no region is configured.
// Route 53 is a global service, so any commercial-partition region works.
const route53DefaultRegion = "us-east-1"

// newRoute53 maps static AWS credentials to the Route 53 libdns provider.
//
// Long-term static credentials are required on purpose: without them the AWS
// SDK falls back to its default credential chain. Session tokens are not
// supported because temporary credentials expire long before renewal.
func newRoute53(cfg map[string]string) (certmagic.DNSProvider, error) {
	accessKeyID := cfg[Route53AccessKeyID]
	secretAccessKey := cfg[Route53SecretAccessKey]
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, errors.New("failed to get Route53 Access Key ID or Secret Access Key")
	}
	region := cmp.Or(cfg[Route53Region], route53DefaultRegion)

	// The upstream provider loads the AWS config lazily and calls log.Fatalf on
	// failure, which still happens with static keys when AWS_* variables are
	// invalid (for example a missing AWS_PROFILE). Load it once here with the
	// same options so the problem is returned as an error instead.
	if _, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
	); err != nil {
		return nil, fmt.Errorf("failed to load AWS config for Route53: %w", err)
	}

	return &route53.Provider{
		AccessKeyId:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
		HostedZoneID:    cfg[Route53HostedZoneID],
	}, nil
}

// init registers AWS Route 53 when its build constraint is satisfied.
func init() {
	register(Definition{Name: Route53, Label: "AWS Route 53", Fields: []Field{
		{Key: Route53AccessKeyID, Label: "Access Key ID", Required: true, Placeholder: "AKIA..."},
		{Key: Route53SecretAccessKey, Label: "Secret Access Key", Secret: true, Required: true},
		{Key: Route53Region, Label: "Region", Placeholder: route53DefaultRegion},
		{Key: Route53HostedZoneID, Label: "Hosted Zone ID", Placeholder: "auto-detect from domain"},
	}}, newRoute53)
}
