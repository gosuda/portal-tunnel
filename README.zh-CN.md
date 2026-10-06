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

Portal 是一个本地隧道运行时和中继网络，用于将服务发布到 Agent 互联网。它通过自托管或公共中继发布本地应用、API、工具和 Agent，把路由和安全策略保留在本地隧道进程中，彻底避免了托管厂商账户或绑卡需求。

- **自托管，完全开源** - 用一条命令运行你自己的中继。MIT 许可证，无任何遥测回传，无企业版门槛。
- **匿名中继网络** - 连接公共中继，或把自托管中继与社区中继组合成具备高可用故障转移的中继池。
- **端到端租户 TLS** - 对于未启用缓存的 HTTPS 流暴露，TLS 在本地隧道进程中终止；中继无法查看明文或会话密钥。
- **基于 IVNP 的覆盖网络** - 需要增强路由隐私时，反向回程流可通过独立的 IVNP 覆盖网络进行传输。
- **内置 MITM 检测** - 主动自探测机制对比两端导出的 TLS 密钥材料，及时发现中继侧 TLS 拦截；`--ban-mitm` 会自动封禁异常中继。
- **无需账户，无需 API Key** - 身份认证采用本地 secp256k1 密钥对（`identity.json`）与 SIWE 挑战签名。
- **原生 x402 支付** - 支持免 gas 的 Sui USDC 或 Casper wCSPR 路由级小额支付，无需传统支付处理机构。

> 📖 **查看完整功能清单**：
> 如需查看 Portal 在 CLI、Agent、SDK 和 Relay 各端支持的全部 20+ 项功能、接口支持情况及信任边界，请参阅**[权威功能清单 (Feature Inventory)](https://gosuda.github.io/portal-tunnel/features)**。

## 对比

| | Portal | ngrok | Cloudflare Tunnel | frp |
|---|---|---|---|---|
| 公共 localhost URL | **支持** | 支持 | 支持 | 支持 |
| 自托管 | **支持** | 仅企业版 | 不支持 | 支持 |
| 开源协议 | **MIT** | 否 | 仅客户端 | Apache 2.0 |
| 自定义域名 | **支持** | 付费方案 | 支持 | 支持 |
| 端到端租户 TLS | **支持（未缓存流）** | 否 | 否 | 否 |
| MITM 自探测 | **支持（导出 TLS 密钥材料）** | 否 | 否 | 否 |
| 多中继故障转移 | **支持** | 托管式 | 内置 | 否 |
| 需要账户 | **不需要** | 需要 | 需要 | 不需要 |
| 原生 x402 支付 | **支持** | 否 | 否 | 否 |

## 快速上手

### 1. 公开本地服务

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

Portal 会立即打印公共 HTTPS 网址。更多常用示例：

```bash
# 自定义名称与显式指定中继
portal expose 3000 --name myapp --relays https://portal.example.com --discovery=false

# 在单个域名下挂载多个本地服务
portal expose --name myapp \
  --http-route /api=http://127.0.0.1:3001 \
  --http-route /=http://127.0.0.1:5173

# 专用原生 TCP 端口（Minecraft、SSH、数据库）
portal expose localhost:25565 --name minecraft --tcp

# 优先使用 IVNP 覆盖网络回程路径
portal expose 3000 --overlay
```

### 2. 使用本地 AI Agent 插件

本仓库为 Codex、Claude Code 和 Cursor 提供了内置 `portal-deploy` 插件（包含 `portal-expose` 和 `portal-connect` 技能）：

```bash
# GitHub CLI
gh skill install gosuda/portal-tunnel portal-deploy/portal-expose

# skills CLI
npx skills add gosuda/portal-tunnel --skill portal-expose
```

对你的 Agent 说：*“用 Portal 把 3000 端口上的应用公开并验证公共网址。”* 详见 [plugins/portal-deploy/README.md](plugins/portal-deploy/README.md)。

### 3. 使用 Portal Agent 管理常驻隧道

需要隧道在后台或作为系统服务持久运行时：

```bash
portal agent run --config config.toml
portal agent dashboard --config config.toml
```

配置语法与服务安装说明请参阅 [Portal Agent 指南](https://gosuda.github.io/portal-tunnel/portal-agent)。

### 4. 运行你自己的中继

数秒内启动自托管开源中继：

```bash
git clone https://github.com/gosuda/portal-tunnel
cd portal-tunnel && cp .env.example .env
docker compose up
```

生产环境配置（ACME 自动化证书、TCP/UDP 端口范围及策略）请参阅 [Deployment 指南](https://gosuda.github.io/portal-tunnel/deployment)。

## 端到端加密工作原理

```text
浏览器
  -> 中继 SNI 路由器  (仅读取路由标识，转发加密密文)
  -> 反向会话
  -> Portal 隧道       (在本地完成 TLS 握手，派生会话密钥)
  -> 本地服务
```

1. **SNI 路由**：中继接收连接，仅读取 TLS ClientHello 中的 SNI 主机名以匹配租约。
2. **密文转发**：中继在不终止 TLS 的情况下，将原始加密字节流直接转入反向会话。
3. **本地握手**：Portal 隧道在本地机器上完成 TLS 握手；会话密钥完全在本地派生。
4. **无私钥签名**：针对中继托管域名，隧道通过中继的 `/v1/sign` 接口获取握手转录本签名，中继始终无法获取会话密钥。
5. **密文保护**：握手完成后，中继继续双向转发密文，无法接触任何明文应用数据。

## 公共中继注册表

Portal 默认包含官方公共中继注册表：

```text
https://raw.githubusercontent.com/gosuda/portal-tunnel/main/registry.json
```

如果你运营公共 Portal 中继，欢迎提交 Pull Request 将中继 URL 添加到 `registry.json`。

## 文档导航

- **[功能清单 (Feature Inventory)](https://gosuda.github.io/portal-tunnel/features)** - 所有产品功能、支持接口与边界的权威清单。
- **[快速入门 (Getting Started)](https://gosuda.github.io/portal-tunnel/getting-started)** - 安装与首次公开教程。
- **[核心概念 (Concepts)](https://gosuda.github.io/portal-tunnel/concepts)** - 中继与隧道所有权模型、传输模式与覆盖网络。
- **[安全模型 (Security Model)](https://gosuda.github.io/portal-tunnel/security-model)** - 租户 TLS、无私钥签名与静态缓存信任边界。
- **[CLI 参考 (CLI Reference)](https://gosuda.github.io/portal-tunnel/cli-reference)** - 完整命令行参数与使用说明。
- **[Portal Agent](https://gosuda.github.io/portal-tunnel/portal-agent)** - 多隧道持久化管理与交互式仪表盘。
- **[自托管指南 (Self-Hosting)](https://gosuda.github.io/portal-tunnel/self-hosting)** - 部署与管理自有中继。
- **[配置参考 (Configuration)](https://gosuda.github.io/portal-tunnel/configuration)** - 环境变量与配置选项说明。
- **[API 参考 (API Reference)](https://gosuda.github.io/portal-tunnel/api-reference)** - 中继网络协议与客户端 API。
- **[维护者架构 (Maintainer Architecture)](docs/maintainer/architecture.md)** - 内部 Go 包结构与数据流说明。

## 贡献

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

MIT License - 详见 [LICENSE](LICENSE)。
