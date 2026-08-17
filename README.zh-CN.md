<p align="center">
  <img src="./logo.png" alt="Portal" width="280" />
</p>

# Portal - 面向 localhost 的自托管中继隧道

[![CI](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/portal-tunnel/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/gosuda/portal-tunnel)](https://github.com/gosuda/portal-tunnel/releases/latest)
[![License](https://img.shields.io/github/license/gosuda/portal-tunnel)](./LICENSE)
[![awesome-tunneling](https://img.shields.io/badge/awesome--tunneling-listed-blue)](https://github.com/anderspitman/awesome-tunneling)

[English](./README.md) | [简体中文](./README.zh-CN.md)

<p align="center"><img width="800" alt="Portal Demo" src="./portal.gif" /></p>

<p align="center"><b>通过自托管或公共中继公开本地服务。</b><br/>无需端口转发。无需入站防火墙规则。无需手动 DNS 配置。无需账户。</p>

## 为什么选择 Portal？

Portal 是一个本地隧道运行时和中继网络。它通过自托管或公共中继发布本地服务，把路由策略保留在隧道进程中，并避免依赖托管式厂商账户。

- **自托管，完全开源** - 用一条命令运行你自己的中继。中继采用 MIT 许可证，没有企业版层级，没有功能门槛，也不会回传遥测。你的中继，你的规则。

- **匿名中继网络** - 无需托管账户或中心化运营方即可连接公共中继。你可以把自托管中继和公共中继组合到一个池中，把信任拆分给你选择的多个独立运营方。

- **端到端租户 TLS 和 ECH** - 因为中继是不可信的，Portal 会在用户端点而不是中继处终止租户 TLS。Portal 还提供 ECH，避免真实主机名以明文 SNI 暴露。

- **内置 MITM 检测** - Portal 会在真实流量开始后主动自探测自己的连接。它会比较两端导出的 TLS 密钥材料，并把不匹配视为疑似中继侧 TLS 终止。

- **多跳中继路由** - 将多个中继串联起来，使单个中继无法同时知道来源和目的地。使用 `--multi-hop-depth 3` 可以自动选择三跳路由。

- **无账户，无 API Key** - 身份认证使用本地生成的 secp256k1 密钥对进行 SIWE 兼容签名。无需邮箱，无需注册，也没有厂商锁定。

- **原生 x402 支付** - Routed HTTP 路径可以在代理前要求 Sui gasless USDC x402 支付。浏览器应用可以导入 `/x402/client.js`，原生客户端可以直接调用 `/x402/prepare` 并发送 `X-PAYMENT`。

## 对比

| | Portal | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| 公共 localhost URL | **是** | 是 | 是 | 是 |
| 可自托管 | **是** | 仅企业版 | 否 | 是 |
| 开源 | **MIT** | 否 | 仅客户端 | Apache 2.0 |
| 自定义域名 | **是** | 付费套餐 | 是 | 是 |
| 端到端租户 TLS | **是** | 否 | 否 | 否 |
| SNI 隐藏 (ECH) | **是** | 否 | 否 | 否 |
| MITM 自探测 | **内置** | 否 | 否 | 否 |
| 多中继故障切换 | **是** | 托管 | 内置 | 否 |
| 多跳路由 | **是** | 否 | 否 | 否 |
| 需要账户 | **否** | 是 | 是 | 否 |
| 原生 x402 支付 | **是** | 否 | 否 | 否 |

## 快速开始

### 公开本地服务

**macOS / Linux:**

```bash
curl -fsSL https://github.com/gosuda/portal-tunnel/releases/latest/download/install.sh | bash
portal expose 3000
```

**Windows (PowerShell):**

```powershell
$ProgressPreference = 'SilentlyContinue'
irm https://github.com/gosuda/portal-tunnel/releases/latest/download/install.ps1 | iex
portal expose 3000
```

Portal 会立即为你的本地应用打印一个公共 HTTPS URL。更多示例：

```bash
# 自定义名称和中继
portal expose 3000 --name myapp --relays https://portal.example.com --discovery=false

# 把前端和 API 挂到同一个 URL 后面
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173

# 在代理某个路由前要求 Sui USDC x402 支付
portal expose --name paid-app \
  --http-route "/paid=http://127.0.0.1:3001 GET:0.01" \
  --http-route /=http://127.0.0.1:5173 \
  --x402-pay-to 0x...

# 原始 TCP 端口（Minecraft、数据库、SSH）
portal expose localhost:25565 --name minecraft --tcp

# 三跳路由，获得更高匿名性
portal expose 3000 --multi-hop-depth 3
```

对于付费路由，支付策略运行在隧道进程内，而不是中继上。默认使用 Sui mainnet；加上 `--x402-testnet` 可切换到 Sui testnet，这个选择与中继自身的支付设置无关。隧道会在同一个公共 origin 上提供 `/x402/client.js` 和 `/x402/prepare`。浏览器前端可以导入 `/x402/client.js` 并调用 `x402Fetch()`；原生客户端可以直接调用 `/x402/prepare`，用自己的 Sui 运行时签名返回的交易，并发送签名后的 `X-PAYMENT`。

完整路由语法请参阅 [CLI Reference](cmd/portal-tunnel/README.md)，x402 helper endpoint 请参阅 [API Reference](docs/src/routes/api-reference/+page.md#payments)。

### 使用本地 AI agent 插件

仓库提供面向 Codex、Claude Code 和 Cursor 的 `portal-deploy` 插件。共用的 `portal-expose` skill 会检查本地应用、打开 Portal 隧道、验证公网 URL，并交接生命周期。

只安装该 skill：

```bash
npx skills add gosuda/portal-tunnel --skill portal-expose
```

加上 `-g` 可安装到所有项目。然后让 agent 用 Portal 部署、预览或分享本地应用。Codex、Claude Code 和 Cursor 的宿主 marketplace 安装步骤见 [plugins/portal-deploy/README.md](plugins/portal-deploy/README.md)。

### 使用 Portal Agent 持续运行隧道

当隧道需要在终端之外持续运行时，使用 `portal agent run`。它会作为本地 OS 服务运行，在一个 TOML 配置中保持所有隧道在线，并提供用于中继和多跳管理的 dashboard。

```bash
portal agent run --config config.toml
portal agent dashboard --config config.toml
portal agent restart
portal agent stop

# 前台模式会跳过 OS 服务安装。
portal agent run --config config.toml --foreground
```

配置格式请参阅 [Portal Agent](docs/src/routes/portal-agent/+page.md)。

### 运行你自己的中继

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel && cp .env.example .env
docker compose up
```

关于带 DNS 自动化（ACME）、TCP/UDP 端口范围和中继策略的公网部署，请参阅 [Deployment](docs/src/routes/deployment/+page.md)。

## 端到端加密如何工作

```text
Browser
  -> Relay SNI router  (只读取路由 token，转发原始字节)
  -> Reverse session
  -> Portal tunnel     (在本地执行 TLS 握手，派生 session key)
  -> Local service
```

1. 中继接受传入连接，并只读取 TLS ClientHello 中用于 SNI 路由的信息。
2. 中继通过反向 session 转发原始加密流，而不终止 TLS。
3. 你这边的 Portal 隧道在本地完成 TLS 握手。Session key 在你的机器上派生。
4. 对于中继托管域名，隧道会通过 `/v1/sign` 获取证书签名，把中继仅用作 keyless signing oracle。中继签署握手摘要，但永远不会接收 session key。
5. 握手完成后，中继继续转发密文，无法访问明文。

启用 ECH 时，中继也看不到真实租户主机名。它会通过从隧道身份派生出的不透明 token 进行路由，而真实 SNI 保留在 ECH 保护的 ClientHello 中。

## 多跳路由如何工作

```text
Browser
  -> Entry relay  (只看到不透明 route hostname)
  -> Middle relay (只看到 next-hop token)
  -> Exit relay   (只看到 reverse session token)
  -> Portal tunnel
  -> Local service
```

链中的每个中继只知道自己的直接相邻节点。没有任何单个中继掌握完整路径。租户 TLS 仍然只在你这边终止，因此链中的任何中继都不会收到租户 TLS 明文。

## 公共中继 Registry

Portal 官方公共中继 registry 是：

```text
https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json
```

隧道客户端默认包含这个 registry。如果你运营公共 Portal 中继，可以提交 pull request，把你的中继 URL 添加到 `registry.json`。

## 文档

- [CLI Reference](cmd/portal-tunnel/README.md)
- [Concepts](docs/src/routes/concepts/+page.md)
- [Portal Agent](docs/src/routes/portal-agent/+page.md)
- [Wallet and ENS](docs/src/routes/wallet-and-ens/+page.md)
- [Security Model](docs/src/routes/security-model/+page.md)
- [Architecture](docs/src/routes/architecture/+page.md)
- [Deployment](docs/src/routes/deployment/+page.md)
- [Configuration Reference](docs/src/routes/configuration/+page.md)

## 贡献

1. Fork 这个仓库。
2. 创建功能分支（`git checkout -b feature/amazing-feature`）。
3. 用聚焦的测试或文档完成修改。
4. 打开 pull request。

## 许可证

MIT License - see [LICENSE](LICENSE).
