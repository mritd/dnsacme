package provider

import (
	"fmt"
	"sort"
	"strings"

	"github.com/caddyserver/certmagic"
)

// Provider names and credential keys are stable external configuration values.
const (
	AliDNS       = "alidns"
	Azure        = "azure"
	Cloudflare   = "cloudflare"
	DuckDNS      = "duckdns"
	Gandi        = "gandi"
	GoDaddy      = "godaddy"
	HuaweiCloud  = "huaweicloud"
	TencentCloud = "tencentcloud"

	DefaultName = Cloudflare

	AliDNSAccessKeyID           = "ALIDNS_ACCKEYID"
	AliDNSAccessKeySecret       = "ALIDNS_ACCKEYSECRET"
	AliDNSRegionID              = "ALIDNS_REGIONID"
	AzureTenantID               = "AZURE_TENANTID"
	AzureClientID               = "AZURE_CLIENTID"
	AzureClientSecret           = "AZURE_CLIENTSECRET"
	AzureSubscriptionID         = "AZURE_SUBSCRIPTIONID"
	AzureResourceGroupName      = "AZURE_RESOURCEGROUPNAME"
	GandiAPIToken               = "GANDI_API_TOKEN"
	CloudflareAPIToken          = "CLOUDFLARE_API_TOKEN"
	GoDaddyAPIToken             = "GODADDY_API_TOKEN"
	DuckDNSAPIToken             = "DUCKDNS_API_TOKEN"
	DuckDNSOverrideDomain       = "DUCKDNS_OVERRIDE_DOMAIN"
	HuaweiCloudAccessKeyID      = "HUAWEICLOUD_ACCKEYID"
	HuaweiCloudAccessKeySecret  = "HUAWEICLOUD_ACCKEYSECRET"
	HuaweiCloudRegionID         = "HUAWEICLOUD_REGIONID"
	TencentCloudAccessKeyID     = "TENCENTCLOUD_ACCKEYID"
	TencentCloudAccessKeySecret = "TENCENTCLOUD_ACCKEYSECRET"
)

// Field describes one dynamic DNS credential field.
type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
}

// Definition describes a compiled DNS provider and its credential fields.
type Definition struct {
	Name   string  `json:"name"`
	Label  string  `json:"label"`
	Fields []Field `json:"fields"`
}

// factory constructs a CertMagic DNS provider from provider-specific values.
type factory func(config map[string]string) (certmagic.DNSProvider, error)

// registeredDefinition keeps public metadata and its private constructor together.
type registeredDefinition struct {
	definition Definition
	factory    factory
}

// registry contains only providers selected by the active build tags.
var registry = make(map[string]registeredDefinition)

// register adds one provider definition and rejects invalid duplicate entries.
func register(definition Definition, fn factory) {
	name := strings.ToLower(definition.Name)
	if name == "" {
		panic("provider name must not be empty")
	}
	if fn == nil {
		panic(fmt.Sprintf("provider %s has no constructor", definition.Name))
	}
	if _, ok := registry[name]; ok {
		panic(fmt.Sprintf("provider %s is already registered", definition.Name))
	}
	definition.Name = name
	definition.Fields = append([]Field(nil), definition.Fields...)
	registry[name] = registeredDefinition{definition: definition, factory: fn}
}

// New constructs a compiled DNS provider from its credential map.
func New(name string, config map[string]string) (certmagic.DNSProvider, error) {
	registered, ok := registry[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS provider: %s", name)
	}
	return registered.factory(config)
}

// Names returns the compiled provider names in lexical order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Default returns the preferred compiled provider, or an empty string when no
// provider was compiled into the binary.
func Default() string {
	if _, ok := registry[DefaultName]; ok {
		return DefaultName
	}
	names := Names()
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// Definitions returns compiled provider metadata with the default provider first.
func Definitions() []Definition {
	definitions := make([]Definition, 0, len(registry))
	for _, registered := range registry {
		definition := registered.definition
		definition.Fields = append([]Field(nil), definition.Fields...)
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool {
		iDefault := definitions[i].Name == DefaultName
		jDefault := definitions[j].Name == DefaultName
		if iDefault != jDefault {
			return iDefault
		}
		return definitions[i].Name < definitions[j].Name
	})
	return definitions
}

// FieldByKey returns a defensive copy of the credential field with the given key.
func FieldByKey(key string) (Field, bool) {
	for _, registered := range registry {
		for _, field := range registered.definition.Fields {
			if field.Key == key {
				return field, true
			}
		}
	}
	return Field{}, false
}
