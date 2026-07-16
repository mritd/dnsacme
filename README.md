<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.svg">
    <img src="assets/logo-wordmark.svg" alt="dnsacme" width="300">
  </picture>
</p>

<p align="center"><a href="README.md">English</a> | <a href="README_CN.md">简体中文</a></p>

<p align="center">Simple tool to manage ACME Cert (Only Supported DNS-01).</p>

### Screenshots

<details>

<img width="2260" height="1458" alt="02-certificate" src="https://github.com/user-attachments/assets/4b7ef49d-34a4-4ef1-84fd-86cf9f0c0b56" />
<img width="2260" height="1458" alt="03-dns-provider" src="https://github.com/user-attachments/assets/a368e93f-c357-4187-b28f-cc2cb01a0044" />
<img width="2260" height="1458" alt="04-auto-update" src="https://github.com/user-attachments/assets/cf8a911a-b09c-4203-abd8-3f7d60c96ef4" />
<img width="2260" height="1458" alt="05-validate-apply" src="https://github.com/user-attachments/assets/ff012938-a95e-4103-9363-76a1152ddc39" />
<img width="2260" height="1458" alt="01-running" src="https://github.com/user-attachments/assets/68294b3d-0f43-4d69-9ae9-088ee8b2525d" />

</details>


### Features

- Support multiple DNS Providers based on CertMagic
- Support custom obtain hook script
- Automatically renew certificates and execute hook scripts
- Support ECC certificate (KeyType can be set)
- Support multiple CA(Let's Encrypt/ZeroSSL)
- Optional DNS providers at compile time (can be used to reduce file size)
- No other dependencies except libc (support muslc)
- Optional Synology DSM package with a native wizard UI and automatic certificate deployment to DSM

### Usage

```sh
~ ❯❯❯ dnsacme --help
Simple tool to manage ACME Cert (Only Supported DNS-01)

Usage:
  dnsacme [flags]

Examples:
  dnsacme --domain='*.example.com' --email='your.example.com' --dns=cloudflare --dns-config=CLOUDFLARE_API_TOKEN=xxxxxxxxxxxxxx

Flags:
  -d, --domain strings              ACME cert domains
  -m, --email string                ACME email
      --storage-dir string          ACME cert status storage directory (default "/root/.config/certmagic")
  -t, --key-type string             ACME cert key type (default "P384")
  -p, --dns string                  ACME DNS provider
      --dns-config stringToString   ACME DNS provider config map (default [])
      --zerossl                     Obtain cert with ZeroSSL CA (default true)
      --obtaining-hook string       CertMagic obtaining hook command
      --obtained-hook string        CertMagic obtained hook command
      --failed-hook string          CertMagic obtain failed hook command
  -l, --list-providers              List supported DNS providers
      --eab-keyid string            ACME Custom EABKeyID
      --eab-mackey string           ACME Custom EABHMACKey
  -h, --help                        help for dnsacme
  -v, --version                     version for dnsacme
```

### Synology DSM Package

dnsacme is also available as a native package for Synology DSM 7.0 and later. The
package adds a wizard to the DSM main menu, imports certificates through the DSM
WebAPI, and runs an unprivileged background daemon for automatic renewal.

- Configure the certificate, DNS provider, and DSM deployment from a native ExtJS wizard.
- Optionally validate a certificate configuration against the Let's Encrypt staging CA without deploying it.
- Import the first certificate into DSM, optionally create it or set it as the DSM default, then re-import future renewals automatically.
- Keep production and staging certificates in separate storage directories.
- Preserve package configuration and certificate storage across package upgrades.

Build the package (produces one SPK per architecture):

```sh
task synology
# build/dnsacme-synology-amd64.spk   x86_64
# build/dnsacme-synology-arm64.spk   aarch64
```

Install the SPK for your NAS architecture through **Package Center > Manual Install**
or over SSH:

```sh
sudo /usr/syno/bin/synopkg install dnsacme-synology-amd64.spk
```

Open **DNSACME** from the DSM main menu after installation. The normal setup flow is:

1. Enter the certificate domain and ACME account email.
2. Select a DNS provider and enter its credentials.
3. Configure the local DSM account and certificate import options.
4. Optionally run **Test Run**. This requests a fresh staging certificate and verifies DSM login, but does not import the certificate. After a successful test, wait at least 10 minutes before applying so DNS caches can discard the staging challenge.
5. Run **Apply** whenever you are ready. This requests the selected production certificate and imports it into DSM. You may apply directly without a staging test, after acknowledging that a production validation failure can count against CA rate limits.

#### Why a DSM administrator password is required

Certificate deployment follows the same approach as the acme.sh Synology deploy hook:
DNSACME signs in to the local DSM WebAPI and asks DSM to import and assign the certificate.
DSM restricts these API operations to administrators, so an administrator account is
required. The alternative would be editing DSM's certificate files directly, which
requires root access and can damage DSM certificate data if a path, permission, or file
is changed incorrectly. DNSACME therefore keeps its daemon unprivileged and uses the DSM
WebAPI instead of modifying certificate files on disk.

##### Audit references

- acme.sh: [DSM WebAPI login](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L228-L233), [certificate lookup and administrator permission check](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L331-L349), and [certificate import](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L364-L383).
- DNSACME: [DSM WebAPI login](synology_deploy.go#L109-L139), [exact certificate lookup](synology_deploy.go#L246-L277), and [certificate import](synology_deploy.go#L159-L244).

The renewal daemon remains idle until **Apply** succeeds for the current configuration.
Changing the domain, DNS credentials, DSM deployment target, or CA mode invalidates the
previous Test and Apply results. Testing remains optional, while a successful production
Apply is always required before automatic renewal starts for the changed configuration.

The package service runs `dnsacme synology daemon` as a foreground process under
DSM's package service manager. Its built-in help is available with:

```sh
/var/packages/dnsacme/target/bin/dnsacme synology --help
/var/packages/dnsacme/target/bin/dnsacme synology daemon --help
```

#### Advanced options

#### Package details

- DSM version: 7.0 or later.
- Architectures: `x86_64` (`amd64`, GOAMD64 v2) and `aarch64` (`arm64`).
- Runtime user: the DSM package account, not root.
- Configuration: `/var/packages/dnsacme/etc/config.yaml` with mode `0600`.
- Certificate and log data: `/var/packages/dnsacme/var`.
- Project link: [github.com/mritd/dnsacme](https://github.com/mritd/dnsacme).

#### Publishing a release

The release task requires a `vMAJOR.MINOR.PATCH` semantic version tag. It builds every
Linux binary and Synology SPK, synchronizes the SPK version with the tag, writes
`build/SHA256SUMS`, tags the current commit, pushes the tag, creates the GitHub
Release, and uploads every file from `build`:

```sh
task release -- v1.2.3
```

By default the latest commit message becomes the release notes. Automated callers can
provide AI-generated notes with `--notes-file`, `RELEASE_NOTES_FILE`, or `RELEASE_NOTES`:

```sh
task release -- v1.2.3 --notes-file /tmp/release.md
```

The GitHub Release title defaults to the tag itself, such as `v1.2.3`.

Regular builds exclude Synology DSM support. Enable it explicitly when building a
DSM-capable binary:

```sh
go build -tags synology
```

`task synology` enables this tag automatically when producing SPK packages.

### DNS Config

Currently dnsacme supports 8 DNS providers (theoretically more, and some have not been added yet),
the providers supported by the `--dns` option can be viewed from here (`DNS_PROVIDER_*`): [consts.go](https://github.com/mritd/dnsacme/blob/main/consts.go)

```sh
DNS_PROVIDER_ALIDNS = "alidns"
DNS_PROVIDER_AZURE = "azure"
DNS_PROVIDER_CLOUDFLARE = "cloudflare"
DNS_PROVIDER_DUCKDNS = "duckdns"
DNS_PROVIDER_GANDI = "gandi"
DNS_PROVIDER_GODADDY = "godaddy"
DNS_PROVIDER_HUAWEICLOUD = "huaweicloud"
DNS_PROVIDER_TENCENTCLOUD = "tencentcloud"
```

For each DNS provider has different configuration, the `--dns-config` option can be specified multiple times:

```sh
dnsacme --dns alidns --dns-config=ALIDNS_ACCKEYID=xxxxxx --dns-config=ALIDNS_ACCKEYSECRET=xxxxxx ...
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
ENV_GODADDY_API_TOKEN = "GODADDY_API_TOKEN"
ENV_DUCKDNS_API_TOKEN = "DUCKDNS_API_TOKEN"
ENV_DUCKDNS_OVERRIDE_DOMAIN = "DUCKDNS_OVERRIDE_DOMAIN"
ENV_HUAWEICLOUD_ACCKEYID = "HUAWEICLOUD_ACCKEYID"
ENV_HUAWEICLOUD_ACCKEYSECRET = "HUAWEICLOUD_ACCKEYSECRET"
ENV_HUAWEICLOUD_REGIONID = "HUAWEICLOUD_REGIONID"
ENV_TENCENTCLOUD_ACCKEYID = "TENCENTCLOUD_ACCKEYID"
ENV_TENCENTCLOUD_ACCKEYSECRET = "TENCENTCLOUD_ACCKEYSECRET"
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

### License

DNSACME is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE)
for attribution information and [TRADEMARKS.md](TRADEMARKS.md) for the project
name and logo policy.
