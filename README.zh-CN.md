# PORTAL - Public Open Relay To Access Localhost

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Portal Demo" src="./portal.gif" /></p>

Portal 可以把本地服务发布到公网，不需要端口转发、NAT 配置或手动 DNS 配置。Portal 是一个可自托管的中继网络，默认让租户 TLS 在你的机器上终止，中继无法读取明文流量。

## 功能

- **本地服务公网 HTTPS**：通过反向连接发布 localhost 服务。
- **端到端租户 TLS**：TLS 在 SDK/客户端侧终止，中继只做 SNI 路由和字节转发。
- **MITM 自探测**：`portal expose` 默认在检测到疑似 TLS 终止时禁用该中继。
- **中继发现和池化**：可以使用公共 registry、显式中继和运行时 discovery 结果。
- **自托管中继**：可以连接公共中继，也可以运行自己的 relay server。
- **Raw TCP/UDP**：支持专用 TCP 端口和 UDP/QUIC datagram backhaul。
- **无需账号/API key**：注册使用 SIWE 身份签名。

## 快速开始

### 暴露本地服务

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

Windows PowerShell:

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

安装细节见 [cmd/portal-tunnel/README.md](cmd/portal-tunnel/README.md)。

### 运行自己的中继

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel && cp .env.example .env
docker compose up
```

公网部署请看 [Deployment](docs/src/routes/deployment/+page.md)，架构说明请看 [Architecture](docs/src/routes/architecture/+page.md)。

## 示例

| 示例 | 说明 |
|---|---|
| [nginx reverse proxy](docs/static/examples/nginx-proxy/) | 在 nginx 后部署 Portal，使用 L4 SNI 路由 |
| [nginx + multi-service](docs/static/examples/nginx-proxy-multi-service/) | 在同一个 nginx 实例后运行 Portal 和其他服务 |

## 公共中继 Registry

官方公共中继 registry:

`https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json`

如果你运行公共 Portal 中继，可以提交 Pull Request 把中继 URL 加入 `registry.json`。

## 安全模型

Portal 的默认 stream 路径中，relay 只读取 TLS ClientHello 中的 SNI 来选择 lease，然后转发加密字节。SDK/客户端侧通过 relay 的 `/v1/sign` keyless signer 完成租户 TLS 握手，但会在本地派生 session key。relay API TLS、租户 TLS、QUIC datagram backhaul TLS 是不同的信任边界。

Raw TCP 和 UDP 端口模式不自动增加租户 TLS。如果这些模式需要保密性，请使用应用层加密。

## License

MIT License - see [LICENSE](LICENSE)
