<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.svg">
    <img src="assets/logo-wordmark.svg" alt="dnsacme" width="300">
  </picture>
</p>

<p align="center"><a href="README.md">English</a> | <a href="README_CN.md">简体中文</a></p>

<p align="center">一个管理 ACME 证书的简单工具，仅支持 DNS-01 验证。</p>

### 界面截图

<details>

<img width="2260" height="1458" alt="02-certificate" src="https://github.com/user-attachments/assets/4b7ef49d-34a4-4ef1-84fd-86cf9f0c0b56" />
<img width="2260" height="1458" alt="03-dns-provider" src="https://github.com/user-attachments/assets/a368e93f-c357-4187-b28f-cc2cb01a0044" />
<img width="2260" height="1458" alt="04-auto-update" src="https://github.com/user-attachments/assets/cf8a911a-b09c-4203-abd8-3f7d60c96ef4" />
<img width="2260" height="1458" alt="05-validate-apply" src="https://github.com/user-attachments/assets/ff012938-a95e-4103-9363-76a1152ddc39" />
<img width="2260" height="1458" alt="01-running" src="https://github.com/user-attachments/assets/68294b3d-0f43-4d69-9ae9-088ee8b2525d" />

</details>

### 功能

- 基于 CertMagic 支持多个 DNS 服务商
- 支持自定义证书申请钩子脚本
- 自动续期证书并执行钩子脚本
- 支持 ECC 证书，可通过 KeyType 设置
- 支持多个 CA，包括 Let's Encrypt 和 ZeroSSL
- 编译时可选择 DNS 服务商，以减小二进制体积
- 除 libc 外没有其他依赖，支持 musl libc
- 提供可选的 Synology DSM 套件，包含原生向导和 DSM 证书自动部署

### 使用方法

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

### Synology DSM 套件

dnsacme 也提供适用于 Synology DSM 7.0 及更高版本的原生套件。套件会在 DSM 主菜单中添加配置向导，通过 DSM WebAPI 导入证书，并以非特权用户运行后台守护进程，自动完成证书续期。

- 通过原生 ExtJS 向导配置证书、DNS 服务商和 DSM 部署选项。
- 可以选择通过 Let's Encrypt staging CA 验证证书配置，测试过程不会部署证书。
- 首次申请后将证书导入 DSM，可选择新建证书或设为 DSM 默认证书，后续续期成功后会自动重新导入。
- 生产证书和 staging 证书使用独立的存储目录。
- 套件升级时保留配置和证书存储。

构建套件，每种架构会生成一个 SPK 文件：

```sh
task synology
# build/dnsacme-synology-amd64.spk   x86_64
# build/dnsacme-synology-arm64.spk   aarch64
```

请根据 NAS 架构，通过 **套件中心 > 手动安装** 安装对应的 SPK，也可以通过 SSH 安装：

```sh
sudo /usr/syno/bin/synopkg install dnsacme-synology-amd64.spk
```

安装完成后，从 DSM 主菜单打开 **DNSACME**。正常配置流程如下：

1. 填写证书域名和 ACME 账户邮箱。
2. 选择 DNS 服务商并填写凭据。
3. 配置本机 DSM 账户和证书导入选项。
4. 可以选择点击 **测试运行**。此操作会申请一张新的 staging 证书并验证 DSM 登录，但不会将证书导入 DSM。测试成功后建议至少等待 10 分钟再应用，让 DNS 缓存中的测试 challenge 失效。
5. 准备好后点击 **应用**。此操作会申请所选的生产证书并导入 DSM。也可以跳过测试直接应用，确认生产环境验证失败可能计入 CA 频率限制即可。

#### 为什么需要 DSM 管理员密码

DNSACME 与 acme.sh 的 Synology 部署逻辑一致，通过本机 DSM WebAPI 登录 DSM，再由 DSM 完成证书导入和分配。这些 API 只允许管理员账户调用，因此需要提供具有管理员权限的 DSM 账户。另一种做法是直接修改 DSM 的证书文件，但这需要 root 权限，路径、权限或文件内容一旦修改错误，还可能损坏 DSM 的证书数据。因此 DNSACME 的守护进程仍以非特权用户运行，只通过 DSM WebAPI 更新证书，不直接改写磁盘上的证书文件。

##### 审计参考

- acme.sh：[DSM WebAPI 登录](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L228-L233)、[证书查询和管理员权限检查](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L331-L349)以及[证书导入](https://github.com/acmesh-official/acme.sh/blob/ebb5cc4981ac38994b124441ef38b961ef565f27/deploy/synology_dsm.sh#L364-L383)。
- DNSACME：[DSM WebAPI 登录](synology_deploy.go#L109-L139)、[精确匹配证书](synology_deploy.go#L246-L277)以及[证书导入](synology_deploy.go#L159-L244)。

#### 切换套件来源后的权限修复

项目自行发布的 SPK 与 SynoCommunity 套件现在统一使用 `sc-dnsacme:synocommunity` 服务身份。较早的项目自有 SPK 使用了不同账户，因此在旧版自有套件与 SynoCommunity 套件之间切换时，保留的配置或证书文件可能无法被新账户读取。DNSACME 不会请求 root 套件钩子自动修改这些文件，因为 DSM 会对此发出安全警告，并可能直接拒绝安装套件。

如果升级后日志中出现 `permission denied`，请使用管理员账户通过 SSH 连接 DSM。首先确认以下命令只解析到 DNSACME 位于 `@appdata`、`@appconf` 和 `@apphome` 下的套件目录：

```sh
readlink -f /var/packages/dnsacme/var
readlink -f /var/packages/dnsacme/etc
readlink -f /var/packages/dnsacme/home
```

确认路径无误后，修复目录所有者并重启套件：

```sh
sudo chown -hR -P sc-dnsacme:synocommunity \
  "$(readlink -f /var/packages/dnsacme/var)" \
  "$(readlink -f /var/packages/dnsacme/etc)" \
  "$(readlink -f /var/packages/dnsacme/home)"
sudo /usr/syno/bin/synopkg restart dnsacme
```

只有当前配置成功完成 **应用** 后，续期守护进程才会开始工作。修改域名、DNS 凭据、DSM 部署目标或 CA 模式后，之前的测试和应用结果会失效。测试仍然可选，但修改后的配置必须成功应用一次才能开始自动续期。

套件服务由 DSM 套件服务管理器运行前台进程 `dnsacme synology daemon`。可以通过以下命令查看内置帮助：

```sh
/var/packages/dnsacme/target/bin/dnsacme synology --help
/var/packages/dnsacme/target/bin/dnsacme synology daemon --help
```

#### 高级选项

#### 套件信息

- DSM 版本：7.0 或更高版本。
- 架构：`x86_64`（`amd64`，GOAMD64 v2）和 `aarch64`（`arm64`）。
- 运行用户：DSM 套件账户，不使用 root。
- 配置文件：`/var/packages/dnsacme/etc/config.yaml`，权限为 `0600`。
- 证书和日志数据：`/var/packages/dnsacme/var`。
- 项目地址：[github.com/mritd/dnsacme](https://github.com/mritd/dnsacme)。

#### 发布新版本

发布任务必须接受 `vMAJOR.MINOR.PATCH` 格式的语义化版本 tag。它会编译所有 Linux 二进制和 Synology SPK，将 SPK 版本与 tag 同步，生成 `build/SHA256SUMS`，为当前 commit 创建并推送 tag，然后创建 GitHub Release 并上传 `build` 中的全部文件：

```sh
task release -- v1.2.3
```

默认使用最新 commit message 作为发布说明。自动化或外部 AI 可以通过 `--notes-file`、`RELEASE_NOTES_FILE` 或 `RELEASE_NOTES` 传入文案：

```sh
task release -- v1.2.3 --notes-file /tmp/release.md
```

GitHub Release 标题默认只使用 tag 本身，例如 `v1.2.3`。

普通构建默认排除 Synology DSM 支持。如需编译包含 DSM 功能的二进制，请显式启用 build tag：

```sh
go build -tags synology
```

`task synology` 在生成 SPK 套件时会自动启用该 tag。

### DNS 配置

dnsacme 当前支持 8 个 DNS 服务商。理论上还可以支持更多服务商，部分服务商尚未添加。`--dns` 参数支持的服务商可以查看 [consts.go](https://github.com/mritd/dnsacme/blob/main/consts.go) 中的 `DNS_PROVIDER_*` 常量：

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

每个 DNS 服务商需要不同的配置。`--dns-config` 参数可以多次指定：

```sh
dnsacme --dns alidns --dns-config=ALIDNS_ACCKEYID=xxxxxx --dns-config=ALIDNS_ACCKEYSECRET=xxxxxx ...
```

各 DNS 服务商使用的配置变量名也可以在 [consts.go](https://github.com/mritd/dnsacme/blob/main/consts.go) 中查看：

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

目前并未实际使用所有 DNS 服务商，因此部分服务商的配置没有经过验证。如果遗漏必填参数，CertMagic 会返回对应错误。

### 钩子命令

- **`cert_obtaining`（`--obtaining-hook`）**：即将申请证书。
  - `renewal`：是否为续期。
  - `identifier`：证书标识符。
  - `forced`：续期时是否强制执行。
  - `remaining`：续期时证书的剩余有效期。
  - `issuer`：之前或当前的签发者。
- **`cert_obtained`（`--obtained-hook`）**：证书申请成功。
  - `renewal`：是否为续期。
  - `identifier`：证书标识符。
  - `remaining`：续期时证书的剩余有效期。
  - `issuer`：之前或当前的签发者。
  - `storage_key`：证书资源在存储中的路径。
- **`cert_failed`（`--failed-hook`）**：证书申请失败。
  - `renewal`：是否为续期。
  - `identifier`：证书标识符。
  - `remaining`：续期时证书的剩余有效期。
  - `issuer`：之前或当前的签发者。
  - `storage_key`：证书资源在存储中的路径。
  - `error`：最终错误信息。

CertMagic 返回对应事件后，dnsacme 会执行关联的钩子命令。你可以编写脚本处理这些事件。

钩子执行时，可以通过环境变量 `ACME_IDENTIFIER` 获取域名。执行 `--obtained-hook` 时，还可以通过 `ACME_CERT_PATH` 和 `ACME_KEY_PATH` 获取证书和私钥的绝对路径。

请确保所有钩子脚本都可以重复执行，也就是满足幂等性，因为同一钩子可能被多次调用。比如每次成功启动后，`--obtained-hook` 都会执行。

### 减小体积

编译时可以只包含指定的 DNS 服务商，从而减小二进制体积：

```sh
# Only include godaddy and cloudflare DNS providers
go build -trimpath -ldflags '-w -s' -tags=slim,godaddy,cloudflare
```

### 环境变量配置

部分用户可能需要通过环境变量定义配置，比如在 Docker 容器中运行时。dnsacme 使用以 `ACME_` 开头的环境变量：

| 环境变量 | 参数 | 示例 |
|----------|------|------|
| `ACME_DOMAIN` | `--domain` | `a.example.com b.example.com` |
| `ACME_STORAGE_DIR` | `--storage-dir` | `/tpm/acme` |
| `ACME_KEY_TYPE` | `--key-type` | `rsa8192` |
| `ACME_DNS_PROVIDER` | `--dns` | `alidns` |
| `ACME_DNS_CONFIG` | `--dns-config` | `{"ALIDNS_ACCKEYID": "xxxxx", "ALIDNS_ACCKEYSECRET": "xxxxx"}` |
| `ACME_ZEROSSL` | `--zerossl` | `true` |
| `ACME_OBTAINING_HOOK` | `--obtaining-hook` | `/opt/scripts/acme-obtaining-hook.sh` |
| `ACME_OBTAINED_HOOK` | `--obtained-hook` | `/opt/scripts/acme-obtained-hook.sh` |
| `ACME_FAILED_HOOK` | `--failed-hook` | `/opt/scripts/acme-failed-hook.sh` |

### 许可证

DNSACME 使用 [Apache License 2.0](LICENSE) 许可证。署名信息请参阅 [NOTICE](NOTICE)，
项目名称和 Logo 的使用规则请参阅 [TRADEMARKS.md](TRADEMARKS.md)。
