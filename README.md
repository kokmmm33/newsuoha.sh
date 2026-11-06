# New-Suoha: Cloudflare Argo + Xray 可视化 Web 管理面板

轻量、极速、零运行时依赖的 Cloudflare Argo 隧道与多协议优选节点 **Web 管理面板**。单静态 Go 二进制内嵌现代响应式前端，支持在主流 Linux VPS（Debian / Ubuntu / CentOS / Fedora / Alpine）上一键部署并常驻运行，可视化管控 **VLESS-WS**、**Trojan-WS** 与 **IPv6 Shadowsocks 直连共存**节点，内置**单端口统一网关**、**永久固定订阅路径**、**二维码扫码导入**及**本地优选 IP 自动测速上传 (`suoha-client`)** 联动。

---

## 致谢与致敬 (Acknowledgments)

本项目基于开源社区优秀成果二次开发与重构，在此特别鸣谢：

* **原版梭哈脚本**：感谢 [jwfst5088/suoha.sh](https://github.com/jwfst5088/suoha.sh) 开拓性的灵感启发与经典梭哈体验。
* **Cloudflare 优选节点提供方**：感谢社区站长们分享的高质量 Cloudflare 优选 CDN 域名（如 `cf.090227.xyz`、`cloudflare.182682.xyz` 等）。
* **XTLS、Cloudflare 与 CloudflareSpeedTest**：感谢 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)、[cloudflare/cloudflared](https://github.com/cloudflare/cloudflared) 与 [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 提供的底层开源技术支持。

---

## 核心特性

* **零依赖单二进制 Web 面板 (`suoha-panel`)**：
  * Go 静态编译并内嵌完整前端静态页面（无需在 VPS 安装 Python / Node.js 环境），原生适配 `amd64`、`arm64`、`armv7`、`386` 四大架构及 Systemd / Alpine OpenRC。
  * 访问根路径 `http://<VPS_IP>:<固定端口>/` 即可打开登录页（内置防爆破频率限制，支持亮/暗双主题与手机端自适应）。
* **单端口合一 + 免开端口 Argo 穿透访问**：
  * **单端口统一网关**：Web 管理面板、订阅服务 (`sub.txt` / `clash.yaml`)、客户端优选上报 API 与本地 WebSocket 分流共用同一个固定端口（自动迁移并兼容旧版 `/etc/suoha_sub_port`）。
  * **免开端口穿透支持**：无公网端口或 NAT 机器可直接通过 Cloudflare Argo 隧道的 `https://` 域名免证书登录 Web 后台与拉取订阅（面板内可随时开关后台穿透权限）。
* **双模式 Argo 隧道常驻守护与自愈**：
  * **梭哈模式 (Quick Tunnel)**：无需自有域名，一键生成 `*.trycloudflare.com` 临时隧道；支持进程异常退出或服务器重启后**自动重连自愈并实时刷新订阅文件**。
  * **固定隧道模式 (CF Zero Trust Token)**：免除繁琐的网页 OAuth `cert.pem` 授权流程，直接在面板粘贴 Cloudflare Zero Trust Tunnel Token 与域名即可；CF 后台只需配置**唯一一条规则**指向本地统一网关端口即可同时打通双协议、HTTPS 订阅与面板。
* **聚焦经典三协议并发共存**：
  * 可视化开关与编辑 **VLESS-WS**、**Trojan-WS** 及 **IPv6 Shadowsocks 直连**节点参数（UUID/密码、WS 路径、节点前缀、TLS 端口），保存后精准热重载 Xray，不中断现有 Argo 隧道。
* **可视化优选管理 + 本地测速客户端联动**：
  * 面板支持手动增删改、多行批量粘贴优选 IP / 优选域名、编辑保底公共优选域名，以及一键切换 Cloudflare TLS 端口（`443` / `2053` / `2083` / `2087` / `2096` / `8443`）。
  * 跨平台本地助手 **`suoha-client`** 定时直连测速并自动上报最优 IP，服务端实时重生成订阅。
* **二维码扫码与 Mihomo 智能分流订阅**：
  * 提供 Base64 通用订阅 (`sub.txt`) 与开箱即用的 **Mihomo / Clash 智能分流配置 (`clash.yaml`)**：基于 MetaCubeX 二进制 `.mrs` 规则集 (`rule-providers`)，内置 `AUTO-优选自动测速` (`url-test`)、`FALLBACK-故障转移` 及 **AI / 流媒体 / YouTube / Google / 电报社交 / GitHub / 游戏平台 / Apple / Microsoft / 服务器运维 / 广告拦截 / 国内直连** 全场景分流策略组，自动对本地测速进程（`suoha-client-*` / `cfst`）强制直连防 TUN 劫持、对节点所属服务器 IP/面板域名提供防断连保护，并配合 `Fake-IP` + 国内外分流 DoH (`respect-rules`) + `Sniffer` 域名嗅探彻底杜绝 DNS 污染与泄露；支持订阅与单节点弹窗扫码、一键唤起客户端导入。

---

## 一键安装 Web 面板

使用 `root` 用户登录 VPS 终端，执行以下命令自动完成安装并启动常驻服务：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/kokmmm33/newsuoha.sh/main/suoha.sh)"
```

如果系统未预装 `curl`，可使用 `wget`：

```bash
bash -c "$(wget -qO- https://raw.githubusercontent.com/kokmmm33/newsuoha.sh/main/suoha.sh)"
```

安装完成后，终端将直接打印：
* **面板访问地址**：`http://<VPS_IP>:<固定端口>/`
* **初始管理员账号与随机密码**
* **通用订阅地址与 Clash 配置地址**

> **旧版无缝升级说明**：若机器此前运行过旧版 `suoha.sh`，安装程序会自动迁移原有的 `/etc/suoha_sub_port`、`/etc/suoha_sub_uuid`、`/etc/suoha_sub_token` 及优选 IP 列表，原有的客户端订阅链接与 `suoha-client` 命令均无需重新配置。

---

## 终端快捷运维命令 (`suoha`)

面板安装后，随时在 SSH 终端输入 `suoha` 即可打开交互式运维菜单，也支持直接执行子命令：

```bash
suoha                # 打开终端交互运维菜单
suoha info           # 查看面板地址、订阅直链与客户端启动命令
suoha reset-pwd      # 随机重置（或指定）面板管理员密码并重启生效
suoha port 28080     # 修改面板与订阅共用的固定监听端口
suoha argo on        # 允许(on) / 禁止(off) 通过 Argo 隧道域名访问管理面板
suoha restart        # 重启面板及托管的隧道服务
suoha update         # 在线更新面板二进制内核（完整保留现有配置）
suoha uninstall      # 彻底卸载服务并清理全部配置与订阅数据
```

---

## Web 面板使用指南

1. **登录面板**：浏览器打开终端输出的 `http://<VPS_IP>:<端口>/`，输入管理员账号与初始密码登录（建议首次登录后在【日志与设置】中修改密码）。
2. **启动隧道（二选一）**：
   * **快速梭哈**：在【隧道管理】选择 **梭哈模式 (Quick Tunnel)**，勾选“启用 Argo 节点隧道常驻运行”，点击 **保存并应用隧道配置**。面板将自动拉取 `xray` 与 `cloudflared` 内核并分配隧道域名。
   * **绑定自有域名**：在 Cloudflare Zero Trust 控制台创建 Tunnel，复制 `eyJ...` 令牌粘贴至面板 **固定隧道 (CF Zero Trust Token)**，并在 CF 后台添加一条 *Public Hostname* 指向面板提示的 `http://127.0.0.1:<面板端口>`。
3. **开启 IPv6 SS 直连共存（可选）**：进入【协议配置】，勾选“启用 IPv6 Shadowsocks 直连共存部署”，点击“自动检测”填入本机公网 IPv6 后保存，即可热重载注入 SS 节点。
4. **扫码或复制订阅**：进入【订阅与节点】，可直接使用客户端扫码、一键唤起导入，或复制直连 HTTP / Argo HTTPS 订阅链接。

---

## 本地优选 IP 自动测速助手 (`suoha-client`)

为了解决不同地区与运营商（电信/联通/移动）下公共优选域名延迟波动的问题，仓库提供了跨平台客户端 **`suoha-client`**（源码位于 [`client/`](client/)，支持 Windows / macOS / Linux / OpenWrt）。

### 方式一：免手动下载 · 终端一键全自动拉取运行（推荐）

直接打开 Web 面板的 **【优选 IP 管理】** 页面复制专属一键命令——脚本会自动识别当前电脑芯片架构（如 Apple Silicon M 系列、Intel、Linux ARM/x86、Windows）、拉取匹配的 Release 客户端、自动处理 `chmod +x` 执行权限与 macOS 隔离属性并立即开始测速上传：

```bash
# macOS / Linux / OpenWrt 单次立即测速上传（去掉 &once=1 即为每 6 小时常驻定时测速）
sh -c "$(curl -fsSL 'http://<VPS_IP>:<固定端口>/api/client.sh?token=<专属Token>&once=1')"
```

```powershell
# Windows PowerShell 单次立即测速上传
powershell -ExecutionPolicy Bypass -Command "irm 'http://<VPS_IP>:<固定端口>/api/client.ps1?token=<专属Token>&once=1' | iex"
```

### 方式二：手动从 Releases 下载对应平台客户端执行

前往 [GitHub Releases (`latest`)](https://github.com/kokmmm33/newsuoha.sh/releases/tag/latest) 下载与你设备匹配的可执行文件（或在面板【优选 IP 管理】中选择对应平台后直接复制命令）：

* **macOS Apple Silicon (M1/M2/M3/M4)**：`suoha-client-darwin-arm64`
* **macOS Intel (x86_64)**：`suoha-client-darwin-amd64`
* **Windows 64 位 / ARM64**：`suoha-client-windows-amd64.exe` / `suoha-client-windows-arm64.exe`
* **Linux / 软路由**：`suoha-client-linux-amd64` / `suoha-client-linux-arm64` / `suoha-client-linux-armv7` / `suoha-client-linux-386`

```bash
# macOS (M 系列芯片示例：赋执行权限 + 清除 Gatekeeper 拦截 + 运行)
chmod +x ./suoha-client-darwin-arm64 && xattr -cr ./suoha-client-darwin-arm64 2>/dev/null
./suoha-client-darwin-arm64 -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>" -once

# Linux / OpenWrt (x86_64 示例：赋执行权限 + 后台定时运行)
chmod +x ./suoha-client-linux-amd64 && ./suoha-client-linux-amd64 -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>"

# Windows PowerShell (64 位示例)
Unblock-File .\suoha-client-windows-amd64.exe -ErrorAction SilentlyContinue
.\suoha-client-windows-amd64.exe -server "http://<VPS_IP>:<固定端口>" -token "<专属Token>" -once
```

> 若服务端开启了单隧道梭哈或固定域名隧道，`-server` 也可直接填写 `https://<Argo隧道域名>`，无需 VPS 开放任何入站端口即可上报优选 IP。

### `suoha-client` 常用参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-server` | 环境变量 `SUOHA_SERVER` | 服务端地址，如 `http://1.2.3.4:28000` 或 `https://sub.example.com` |
| `-token` | 环境变量 `SUOHA_TOKEN` | 面板【优选 IP 管理】中显示的客户端鉴权 Token |
| `-interval` | `6h` | 后台循环测速间隔（如 `6h`、`2h`、`30m`） |
| `-once` | `false` | 单次运行模式，完成一次测速与上传后立即退出 |
| `-top` | `5` | 每次挑选并上传的最优 IP 数量 |
| `-port` | `443` | 优选节点使用的 Cloudflare TLS 端口（如 `443`、`2053`、`8443`） |
| `-dd` | `false` | 禁用下载测速，仅按延迟筛选优选 IP |
| `-ipv6` | `false` | 使用 IPv6 地址段（`ipv6.txt`）进行测速优选 |
| `-tl` | `300` | 平均延迟上限（ms） |
| `-sl` | `0` | 下载速度下限（MB/s，默认不限制） |
| `-config` | `./config.json` | JSON 配置文件路径（参考 [`client/config.example.json`](client/config.example.json)） |

---

## 从源码编译

仓库包含服务端 [`panel/`](panel/) 与客户端 [`client/`](client/) 两个独立的零外部依赖 Go 模块（仅依赖 Go 1.22+ 标准库，无需安装 Node.js 或 C 编译器）：

```bash
# 编译服务端面板 (自动通过 go:embed 打包 web/ 前端资源)
cd panel && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/suoha-panel .

# 编译本地优选客户端
cd ../client && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/suoha-client .
```

---

## 免责声明

本项目仅供技术研究、网络运维测试及协议学习使用。使用者请严格遵守当地法律法规，切勿用于任何违反法律或危害网络安全的行为。
