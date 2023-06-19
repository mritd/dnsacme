## DNSACME

Simple tool to manage ACME Cert(Ony Supported DNS-01).

### Features

- Support multiple DNS Providers based on CertMagic
- Support custom obtain hook script
- Automatically renew certificates and execute hook scripts
- Support ECC certificate (KeyType can be set)
- Support multiple CA(Let's Encrypt/ZeroSSL)
- Optional DNS providers at compile time (can be used to reduce file size)
- No other dependencies except libc (support muslc)

### Usage

```sh
~ ❯❯❯ dnsacme --help
Simple tool to manage ACME Cert(Ony Supported DNS-01)

Usage:
  dnsacme [flags]

Examples:
  dnsacme --domain='*.example.com' --dns=cloudflare --dns-config=CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxx

Flags:
  -d, --domain strings              ACME cert domains
  -m, --email string                ACME email (default "caddy@zerossl.com")
      --storage-dir string          ACME cert status storage directory (default "/Users/kovacs/Library/Application Support/dnsacme")
  -t, --key-type string             ACME cert key type (default "P384")
  -p, --dns string                  ACME DNS provider
      --dns-config stringToString   ACME DNS provider config map (default [])
      --zerossl                     Obtain cert with ZeroSSL CA (default true)
      --obtaining-hook string       CertMagic obtaining hook command
      --obtained-hook string        CertMagic obtained hook command
      --failed-hook string          CertMagic obtain failed hook command
      --list-providers              List supported DNS providers
  -h, --help                        help for dnsacme
```

### DNS Config

Currently dnsacme only supports 10 DNS providers (theoretically more, and some have not been added yet), 
the providers supported by the `--dns` option can be viewed from here (`DNS_PROVIDER_*`): [consts.go](https://github.com/mritd/dnsacme/blob/main/consts.go)

```sh
DNS_PROVIDER_ALIDNS = "alidns"
DNS_PROVIDER_AZURE = "azure"
DNS_PROVIDER_CLOUDFLARE = "cloudflare"
DNS_PROVIDER_DNSPOD = "dnspod"
DNS_PROVIDER_DUCKDNS = "duckdns"
DNS_PROVIDER_GANDI = "gandi"
DNS_PROVIDER_GODADDY = "godaddy"
DNS_PROVIDER_NAMEDOTCOM = "namedotcom"
DNS_PROVIDER_VULTR = "vultr"
```

For each DNS provider has different configuration, the `--dns-config` option can be specified multiple times:

```sh
dnsacme --dns aliydns --dns-config=ALIDNS_ACCKEYID=xxxxxx --dns-config=ALIDNS_ACCKEYSECRET=xxxxxx ...
```

The configuration variable Key of each DNS provider can also be found in [consts.go](https://github.com/mritd/dnsacme/blob/main/consts.go):

```sh
ENV_ALIDNS_ACCKEYID = "ALIDNS_ACCKEYID"
ENV_ALIDNS_ACCKEYSECRET = "ALIDNS_ACCKEYSECRET"
ENV_ALIDNS_REGIONID = "ALIDNS_REGIONID"
ENV_AZURE_TENANTID = "AZURE_TENANTID"
ENV_AZURE_CLIENTID = "AZURE_CLIENTID"
ENV_AZURE_CLIENTSECRET = "AZURE_CLIENTSECRET"
ENV_AZURE_SUBSCRIPTIONID = "AZURE_SUBSCRIPTIONID"
ENV_AZURE_RESOURCEGROUPNAME = "AZURE_RESOURCEGROUPNAME"
ENV_GANDI_API_TOKEN = "GANDI_API_TOKEN"
ENV_CLOUDFLARE_API_TOKEN = "CLOUDFLARE_API_TOKEN"
ENV_NAMEDOTCOM_TOKEN = "NAMEDOTCOM_TOKEN"
ENV_NAMEDOTCOM_USER = "NAMEDOTCOM_USER"
ENV_NAMEDOTCOM_SERVER = "NAMEDOTCOM_SERVER"
ENV_GODADDY_API_TOKEN = "GODADDY_API_TOKEN"
ENV_VULTR_API_TOKEN = "VULTR_API_TOKEN"
ENV_DNSPOD_API_TOKEN = "DNSPOD_API_TOKEN"
ENV_DUCKDNS_API_TOKEN = "DUCKDNS_API_TOKEN"
ENV_DUCKDNS_OVERRIDE_DOMAIN = "DUCKDNS_OVERRIDE_DOMAIN"
```

**Currently, I don't use all DNS providers, so the configuration for some DNS providers is not verified in the code;**
** for example, some parameters are required, but you don't set them, then an error in the CertMagic library will be returned. **

### Hook Command

- **`cert_obtaining`(`--obtaining-hook`)** A certificate is about to be obtained
  - `renewal`: Whether this is a renewal
  - `identifier`: The name on the certificate
  - `forced`: Whether renewal is being forced (if renewal)
  - `remaining`: Time left on the certificate (if renewal)
  - `issuer`: The previous or current issuer
- **`cert_obtained`(`--obtained-hook`)** A certificate was successfully obtained
  - `renewal`: Whether this is a renewal
  - `identifier`: The name on the certificate
  - `remaining`: Time left on the certificate (if renewal)
  - `issuer`: The previous or current issuer
  - `storage_key`: The path to the cert resources within storage
- **`cert_failed`(`--failed-hook`)** An attempt to obtain a certificate failed
  - `renewal`: Whether this is a renewal
  - `identifier`: The name on the certificate
  - `remaining`: Time left on the certificate (if renewal)
  - `issuer`: The previous or current issuer
  - `storage_key`: The path to the cert resources within storage
  - `error`: The (final) error message

When CertMagic returns the target Events, the corresponding hook command will be executed, and you can write scripts to handle the corresponding events.

**When the hook is executing, you can get the domain name from the environment through the `ACME_IDENTIFIER` variable;**
**When `--obtained-hook` is executing, you can also get the absolute path of the certificate and key through `ACME_CERT_PATH` and the `ACME_KEY_PATH` variable.**


**⚠️Note: You need to ensure that all hook scripts can be executed repeatedly (idempotent), because they may be called multiple times. For example,**
**`--obtained-hook` will be executed after each successful startup.**

### Reduced size

Other DNS providers can be deleted by specifying the DNS provider at compile time, which will reduce the file size:

```sh
# Only include godaddy and cloudflare DNS providers
go build -trimpath -ldflags '-w -s' -tags=slim,godaddy,cloudflare
```

### ENV Config

Some users may need to use environment variables to define configuration, for example in the dcoker container.
dnsacme uses environment variables prefixed with `ACME_`, which are defined as follows:

| ENV KEY               | FLAG               | Example                                                        |
|-----------------------|--------------------|----------------------------------------------------------------|
| `ACME_DOMAIN`         | `--domain`         | `a.example.com b.example.com`                                  |
| `ACME_STORAGE_DIR`    | `--storage-dir`    | `/tpm/acme`                                                    |
| `ACME_KEY_TYPE`       | `--key-type`       | `rsa8192`                                                      |
| `ACME_DNS_PROVIDER`   | `--dns`            | `alidns`                                                       |
| `ACME_DNS_CONFIG`     | `--dns-config`     | `{"ALIDNS_ACCKEYID": "xxxxx", "ALIDNS_ACCKEYSECRET": "xxxxx"}` |
| `ACME_ZEROSSL`        | `--zerossl`        | `true`                                                         |
| `ACME_OBTAINING_HOOK` | `--obtaining-hook` | `/opt/scripts/acme-obtaining-hook.sh`                          |
| `ACME_OBTAINED_HOOK`  | `--obtained-hook`  | `/opt/scripts/acme-obtained-hook.sh`                           |
| `ACME_FAILED_HOOK`    | `--failed-hook`    | `/opt/scripts/acme-failed-hook.sh`                             |




