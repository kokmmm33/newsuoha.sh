# New-Suoha: Cloudflare Argo + Xray 一键全自动脚本

轻量、极速、开箱即用的多协议隧道穿透脚本。支持在主流 Linux 系统的 VPS 上一键并发部署 **VLESS-WS** 与 **Trojan-WS** 节点，通过 Cloudflare Argo 隧道实现穿透免开端口，同时矩阵式输出多组优选 CDN 域名与 443 TLS 节点。内置**永久固定订阅端口**服务与 **IPv6 Shadowsocks 直连共存**能力，支持订阅无缝更新及主流客户端一键导入。

---

## 致谢与致敬 (Acknowledgments)

本项目基于开源社区优秀成果二次开发与重构，在此特别鸣谢：

* **原版梭哈脚本**：感谢 [jwfst5088/suoha.sh](https://github.com/jwfst5088/suoha.sh) 开拓性的灵感启发与基础实现，经典梭哈模式为轻量化 Argo 部署奠定了极简实用的体验基础。
* **Cloudflare 优选节点提供方**：感谢社区与站长们无私维护并分享的高质量 Cloudflare 优选 CDN 域名（如 `cf.090227.xyz`、`cloudflare.182682.xyz` 等），极大改善了国内到 Cloudflare 边缘网络的延迟与连接质量。
* **XTLS 与 Cloudflare**：感谢 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 与 [cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) 提供的底层开源技术支持。

---

## 核心特性

* **多架构与多系统适配**：原生支持 `x86_64`、`arm64`、`armv7l`、`i386` 架构；全面适配 Debian、Ubuntu、CentOS、Fedora 及 Alpine Linux。
* **无需自有域名**：默认提供 **梭哈模式 (Quick Tunnel)**，无需自有域名和证书，自动生成临时 `*.trycloudflare.com` 域名打通隧道。
* **支持固定隧道托管**：提供 **安装服务模式 (Named Tunnel)**，支持绑定托管在 Cloudflare 上的自定义二级域名，并注册 Systemd / OpenRC 开机常驻自启。
* **双协议原生并发**：单次部署同时启动 VLESS-WS 与 Trojan-WS 协议，各分配原生监听与独立 Quick Tunnel 隧道，无协议握手断流问题。
* **IPv6 Shadowsocks 共存**：支持一键追加部署 IPv6 SS 直连节点（AES-128-GCM 加密），与原有 Argo 隧道节点完全共存且自动合并至订阅源。
* **矩阵式 443 TLS 优选节点**：
* 自动为每个协议矩阵生成 **3 组优选域名**节点：
* `默认 Argo 域名`
* `cf.090227.xyz`
* `cloudflare.182682.xyz`


* 纯粹聚焦 **443 TLS** 标准节点，移除 80 端口明文节点，保障链路加密与 CDN 握手稳定性。


* **永久固定订阅端口与安全路径（免重复导入）**：
* 首次运行自动分配并持久化记录订阅端口（存储于 `/etc/suoha_sub_port`）与随机安全路径 UUID（存储于 `/etc/suoha_sub_uuid`）；
* 静态订阅文件集中托管于 `/var/www/suoha_sub/<UUID>/`（并内置空 `index.html` 屏蔽目录遍历防扫描泄露），重新梭哈或重启服务器后，**客户端无需重新导入链接，直接点击“更新订阅”即可自动刷新最新节点**。



---

## 一键运行命令

登录 VPS 终端（支持 root 用户），执行以下命令即可启动交互菜单：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/a6216abcd/newsuoha.sh/refs/heads/main/suoha.sh)"

```

如果系统未预装 `curl`，可使用 `wget` 代替：

```bash
bash -c "$(wget -qO- https://raw.githubusercontent.com/a6216abcd/newsuoha.sh/refs/heads/main/suoha.sh)"

```

---

## 交互菜单说明

```text
1. 梭哈模式 (自动生成 VLESS+Trojan 443 TLS 优选节点)
2. 安装服务 (自定义域名绑定固定隧道)
3. 卸载服务
4. 清空缓存
5. 额外增加ipv6 ss 共存部署
0. 退出脚本

```

### 1. 梭哈模式 (推荐快速使用)

运行脚本选择 `1`（或直接按回车）：

1. 选择 Argo 连接网络模式（输入 `4` 为 IPv4，`6` 为 IPv6，默认 `4`）。
2. 脚本自动拉取对应架构的 `Xray-core` 与 `cloudflared`。
3. 双实例分别建立 VLESS-WS 与 Trojan-WS 的专属临时隧道。
4. 自动生成多组 443 TLS 节点，并由本地 Python HTTP 服务在固定端口提供订阅服务。

### 2. 安装服务模式 (长期稳定托管)

如果拥有在 Cloudflare 托管的自有域名：

1. 运行脚本选择 `2`。
2. 复制控制台生成的 Cloudflare 授权链接在浏览器完成授权。
3. 输入想要绑定的二级域名（如 `sub.example.com`）。
4. 脚本自动创建命名隧道（Named Tunnel）并配置 DNS 路由解析，同时注册系统服务开机自启。
5. 后续直接在终端输入 `suoha` 即可随时呼出管理面板。

### 3. 额外增加 IPv6 SS 共存部署

在已运行【梭哈模式】或【安装服务】的前提下：

1. 运行脚本选择 `5`。
2. 脚本自动检测外网公网 IPv6 地址。
3. 在 Xray 中注入监听 `::` 的 Shadowsocks 入站，精准重载 Xray 进程，不影响现有 Argo 隧道。
4. 自动生成 `ss://` 直连链接，并追加合并至现有订阅文件，客户端直接刷新订阅即可同步获取。

---

## 节点与订阅导入说明

| 导入目标 | 说明 | 示例格式 / 路径 |
| --- | --- | --- |
| **通用订阅 (v2rayN / NekoBox / Shadowrocket)** | 复制输出的通用订阅 URL 直接粘贴添加订阅 | `http://<VPS_IP>:<固定端口>/<随机UUID>/sub.txt` |
| **应用协议快速导入** | 复制并导入 `sub://` 深度链接快速调起客户端 | `sub://http://<VPS_IP>:<固定端口>/<随机UUID>/sub.txt` |
| **Clash / Mihomo 一键配置** | 点击或导入配置链接直接拉取代理策略组 | `clash://install-config?url=http://<VPS_IP>:<固定端口>/<随机UUID>/clash.yaml` |
| **Clash 原始配置文件直链** | 浏览器直接下载或作为远程配置链接输入 | `http://<VPS_IP>:<固定端口>/<随机UUID>/clash.yaml` |
| **单节点手动导入** | 支持独立复制导入 | `vless://...`、`trojan://...`、`ss://...` |

### 本地持久化文件结构

* **持久订阅目录**：`/var/www/suoha_sub/<随机UUID>/`
  * `nodes.txt`：当前所有可用节点的明文连接串
  * `sub.txt`：Base64 编码的通用客户端订阅源
  * `clash.yaml`：适用于 Clash/Mihomo 的完整策略组配置文件
  * `meta.json` / `preferred_ips.json` / `sub_server.py`（位于 `/var/www/suoha_sub/`）：当前隧道配置元数据、客户端上传的动态优选 IP 列表及后台 HTTP 服务
* **固定订阅端口与安全路径记录**：`/etc/suoha_sub_port`、`/etc/suoha_sub_uuid`
* **固定鉴权 Token 记录**：`/etc/suoha_sub_token`
* **运行主目录**：
  * 梭哈模式：`/opt/suoha_quick/`
  * 安装服务模式：`/opt/suoha/`

---

## 客户端本地优选 IP 自动测速与上传 (`suoha-client`)

为了解决不同地区、不同宽带运营商（电信/联通/移动）下公共优选域名延迟不稳定的问题，本项目提供了跨平台的本地后台优选助手 **`suoha-client`**（源码位于 [`client/`](client/)，支持 Windows / macOS / Linux / OpenWrt 软路由）。

### 工作流程

1. **自动准备测速环境**：首次运行若本地无 `CloudflareSpeedTest` 或 IP 段文件（`ip.txt` / `ipv6.txt`），程序会根据当前系统与架构自动下载解压。
2. **强制物理直连测速**：调用 `CloudflareSpeedTest` 子进程时自动剥离本地 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 环境变量，确保测得真实的本地直连延迟与下载速度。
3. **自动上传并刷新服务端订阅**：筛选出最优的 Top N（默认 5 个）IP，附带机房/延迟/速度标签（如 `优选1-HKG-38ms-21.5MB`）通过 `POST /api/update_ips` 上传至服务端。
4. **服务端无感热更新**：服务端收到优选列表后，立即将动态优选 IP 置顶合并（同时保留默认 Argo 域名、内置公共优选域名作为保底，以及共存的 IPv6 SS 节点），自动重生成 `sub.txt` 与 `clash.yaml`。

### 快速使用

服务端部署完成后，终端（或 `v2ray.txt`）会直接输出专属的启动命令：

```bash
# Linux / macOS / OpenWrt 后台定时运行（默认每 6 小时自动测速并上传 Top 5 优选 IP）
./suoha-client -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>"

# Windows (CMD / PowerShell)
suoha-client.exe -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>"

# 单次立即测速并上传后退出（适合配合 crontab 或计划任务）
./suoha-client -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>" -once
```

### 常用参数说明

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-server` | 环境变量 `SUOHA_SERVER` | 服务端订阅地址，如 `http://1.2.3.4:28000` |
| `-token` | 环境变量 `SUOHA_TOKEN` | 服务端 `/etc/suoha_sub_token` 中的鉴权 Token |
| `-interval` | `6h` | 后台循环测速间隔（如 `6h`、`2h`、`30m`） |
| `-once` | `false` | 单次运行模式，完成一次测速与上传后立即退出 |
| `-top` | `5` | 每次挑选并上传的最优 IP 数量 |
| `-port` | `443` | 优选节点使用的 Cloudflare TLS 端口（如 `443`、`2053`、`2083`、`8443`） |
| `-dd` | `false` | 禁用下载测速，仅按延迟筛选优选 IP（速度快、省流量） |
| `-ipv6` | `false` | 使用 IPv6 地址段（`ipv6.txt`）进行测速优选 |
| `-tl` | `300` | 平均延迟上限（ms） |
| `-sl` | `0` | 下载速度下限（MB/s，默认不限制） |
| `-url` | 空 | 自定义 `CloudflareSpeedTest` 下载测速地址 |
| `-cfst-dir` | `./cfst` | `CloudflareSpeedTest` 及 IP 段文件存放目录 |
| `-cfst-args` | 空 | 额外透传给 `CloudflareSpeedTest` 的原始命令行参数 |
| `-config` | `./config.json` | JSON 配置文件路径（参考 [`client/config.example.json`](client/config.example.json)） |

---

## 卸载与清理

* 运行脚本选择 `3. 卸载服务`，脚本将自动：
  * 停止并清理 Xray、cloudflared 及后台内置 HTTP 订阅服务进程；
  * 移除 systemd 单元文件（或 Alpine OpenRC 脚本）；
  * 清理 `/opt/suoha`、`/opt/suoha_quick`、`/var/www/suoha_sub`、`/etc/suoha_sub_port`、`/etc/suoha_sub_token` 及全局命令软链接 `suoha`。



---

## 免责声明

本脚本仅供技术研究、网络运维测试及协议学习使用。使用者请严格遵守当地法律法规，切勿用于任何违反法律或危害网络安全的行为。
