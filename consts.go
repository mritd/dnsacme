package main

const (
	/**
	 * All supported DNS providers names
	 */

	DNS_PROVIDER_ALIDNS     = "alidns"
	DNS_PROVIDER_AZURE      = "azure"
	DNS_PROVIDER_CLOUDFLARE = "cloudflare"
	DNS_PROVIDER_DNSPOD     = "dnspod"
	DNS_PROVIDER_DUCKDNS    = "duckdns"
	DNS_PROVIDER_GANDI      = "gandi"
	DNS_PROVIDER_GODADDY    = "godaddy"
	DNS_PROVIDER_NAMEDOTCOM = "namedotcom"
	DNS_PROVIDER_NAMESILO   = "namesilo"
	DNS_PROVIDER_VULTR      = "vultr"

	/**
	 * Configuration variables for all supported DNS providers
	 */

	ENV_ALIDNS_ACCKEYID         = "ALIDNS_ACCKEYID"
	ENV_ALIDNS_ACCKEYSECRET     = "ALIDNS_ACCKEYSECRET"
	ENV_ALIDNS_REGIONID         = "ALIDNS_REGIONID"
	ENV_AZURE_TENANTID          = "AZURE_TENANTID"
	ENV_AZURE_CLIENTID          = "AZURE_CLIENTID"
	ENV_AZURE_CLIENTSECRET      = "AZURE_CLIENTSECRET"
	ENV_AZURE_SUBSCRIPTIONID    = "AZURE_SUBSCRIPTIONID"
	ENV_AZURE_RESOURCEGROUPNAME = "AZURE_RESOURCEGROUPNAME"
	ENV_GANDI_API_TOKEN         = "GANDI_API_TOKEN"
	ENV_CLOUDFLARE_API_TOKEN    = "CLOUDFLARE_API_TOKEN"
	ENV_NAMEDOTCOM_TOKEN        = "NAMEDOTCOM_TOKEN"
	ENV_NAMEDOTCOM_USER         = "NAMEDOTCOM_USER"
	ENV_NAMEDOTCOM_SERVER       = "NAMEDOTCOM_SERVER"
	ENV_GODADDY_API_TOKEN       = "GODADDY_API_TOKEN"
	ENV_NAMESILO_API_TOKEN      = "NAMESILO_API_TOKEN"
	ENV_VULTR_API_TOKEN         = "VULTR_API_TOKEN"
	ENV_DNSPOD_API_TOKEN        = "DNSPOD_API_TOKEN"
	ENV_DUCKDNS_API_TOKEN       = "DUCKDNS_API_TOKEN"
	ENV_DUCKDNS_OVERRIDE_DOMAIN = "DUCKDNS_OVERRIDE_DOMAIN"

	LOGO = `
██████╗███╗   █████████╗     █████╗ █████████╗   ██████████╗
██╔══██████╗  ████╔════╝    ██╔══████╔════████╗ ██████╔════╝
██║  ████╔██╗ █████████╗    █████████║    ██╔████╔███████╗  
██║  ████║╚██╗██╚════██║    ██╔══████║    ██║╚██╔╝████╔══╝  
██████╔██║ ╚███████████║    ██║  ██╚████████║ ╚═╝ █████████╗
╚═════╝╚═╝  ╚═══╚══════╝    ╚═╝  ╚═╝╚═════╚═╝     ╚═╚══════╝
`
)
