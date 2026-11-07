#!/usr/bin/env bash
# New-Suoha Web 管理面板 一键安装与终端运维脚本
# 支持系统: Debian / Ubuntu / CentOS / Fedora / Rocky / AlmaLinux (Systemd) & Alpine (OpenRC)
# 支持架构: x86_64 (amd64) / aarch64 (arm64) / armv7l (armv7) / i386 (386)

set -u

SUOHA_REPO="${SUOHA_REPO:-kokmmm33/newsuoha.sh}"
SUOHA_TAG="${SUOHA_TAG:-latest}"
DATA_DIR="/opt/suoha"
PANEL_BIN="${DATA_DIR}/suoha-panel"
SCRIPT_DEST="${DATA_DIR}/suoha.sh"
GLOBAL_CMD="/usr/bin/suoha"
SERVICE_NAME="suoha-panel"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[信息]${NC} $*"; }
ok()    { echo -e "${GREEN}[成功]${NC} $*"; }
warn()  { echo -e "${YELLOW}[提示]${NC} $*"; }
err()   { echo -e "${RED}[错误]${NC} $*" >&2; }

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "请使用 root 用户运行本脚本 (例如: sudo bash suoha.sh)"
        exit 1
    fi
}

is_alpine() {
    [ -f /etc/alpine-release ] || grep -qi "Alpine" /etc/os-release 2>/dev/null
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk"
    else
        echo "unknown"
    fi
}

ensure_base_deps() {
    if command -v curl >/dev/null 2>&1; then
        return 0
    fi
    local pm
    pm=$(detect_pkg_manager)
    info "正在安装基础网络工具 curl 與根证书..."
    case "$pm" in
        apt)
            apt-get update -y >/dev/null 2>&1
            apt-get install -y curl ca-certificates >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y curl ca-certificates >/dev/null 2>&1
            ;;
        yum)
            yum install -y curl ca-certificates >/dev/null 2>&1
            ;;
        apk)
            apk update >/dev/null 2>&1
            apk add --no-cache curl ca-certificates >/dev/null 2>&1
            ;;
        *)
            err "未检测到 curl 且无法识别包管理器，请先手动安装 curl"
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64)
            echo "amd64"
            ;;
        aarch64 | arm64 | armv8*)
            echo "arm64"
            ;;
        armv7l | armv7*)
            echo "armv7"
            ;;
        i386 | i686)
            echo "386"
            ;;
        *)
            err "当前处理器架构 $(uname -m) 暂未适配"
            exit 1
            ;;
    esac
}

cleanup_legacy_processes() {
    # 停止旧版脚本遗留的独立进程，释放端口以便 suoha-panel 接管，但保留 /etc/suoha_sub_* 供自动迁移
    pkill -f "sub_server.py" >/dev/null 2>&1 || true
    if [ -f "/etc/suoha_sub_port" ]; then
        local old_port
        old_port=$(tr -d '\r\n ' < /etc/suoha_sub_port)
        if [ -n "$old_port" ]; then
            pkill -f "http.server ${old_port}" >/dev/null 2>&1 || true
        fi
    fi

    for pidf in /opt/suoha_quick/xray.pid /opt/suoha_quick/cf_vl.pid /opt/suoha_quick/cf_tr.pid; do
        if [ -f "$pidf" ]; then
            kill -9 "$(cat "$pidf")" >/dev/null 2>&1 || true
            rm -f "$pidf"
        fi
    done

    if is_alpine; then
        rm -f /etc/local.d/cloudflared.start /etc/local.d/xray.start
    else
        if command -v systemctl >/dev/null 2>&1; then
            for svc in cloudflared.service xray.service; do
                if [ -f "/lib/systemd/system/${svc}" ] || [ -f "/etc/systemd/system/${svc}" ]; then
                    systemctl stop "$svc" >/dev/null 2>&1 || true
                    systemctl disable "$svc" >/dev/null 2>&1 || true
                    rm -f "/lib/systemd/system/${svc}" "/etc/systemd/system/${svc}"
                fi
            done
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    fi
}

download_panel_binary() {
    local arch
    arch=$(detect_arch)
    local asset="suoha-panel-linux-${arch}"
    local tmp_bin="${PANEL_BIN}.download"
    mkdir -p "$DATA_DIR"

    # 若在源码仓库本地执行且安装了 Go，优先支持本地构建回退
    local script_dir
    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo "")

    local urls=()
    if [ "$SUOHA_TAG" = "latest" ]; then
        urls+=(
            "https://github.com/${SUOHA_REPO}/releases/download/latest/${asset}"
            "https://github.com/${SUOHA_REPO}/releases/latest/download/${asset}"
            "https://ghfast.top/https://github.com/${SUOHA_REPO}/releases/download/latest/${asset}"
            "https://ghproxy.net/https://github.com/${SUOHA_REPO}/releases/download/latest/${asset}"
        )
    else
        urls+=(
            "https://github.com/${SUOHA_REPO}/releases/download/${SUOHA_TAG}/${asset}"
            "https://ghfast.top/https://github.com/${SUOHA_REPO}/releases/download/${SUOHA_TAG}/${asset}"
            "https://ghproxy.net/https://github.com/${SUOHA_REPO}/releases/download/${SUOHA_TAG}/${asset}"
        )
    fi

    info "正在拉取面板服务端二进制 (${asset})..."
    local downloaded=0
    for u in "${urls[@]}"; do
        if curl -fL --connect-timeout 10 --max-time 120 "$u" -o "$tmp_bin" >/dev/null 2>&1; then
            if [ -s "$tmp_bin" ] && [ "$(wc -c < "$tmp_bin")" -gt 500000 ]; then
                downloaded=1
                break
            fi
        fi
    done

    if [ "$downloaded" -eq 0 ] && [ -n "$script_dir" ] && [ -f "${script_dir}/panel/main.go" ] && command -v go >/dev/null 2>&1; then
        warn "远程 Release 未就绪或无法连接，检测到本地源码与 Go 环境，正在本地编译 suoha-panel..."
        if (cd "${script_dir}/panel" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$tmp_bin" .); then
            downloaded=1
        fi
    fi

    if [ "$downloaded" -eq 0 ]; then
        rm -f "$tmp_bin"
        err "下载 ${asset} 失败，请检查网络连接或确认仓库 ${SUOHA_REPO} 已发布 Release 构建产物。"
        exit 1
    fi

    chmod +x "$tmp_bin"
    mv -f "$tmp_bin" "$PANEL_BIN"
    ok "suoha-panel 内核已部署至 ${PANEL_BIN}"
}

install_management_script() {
    mkdir -p "$DATA_DIR"
    local self_path="${BASH_SOURCE[0]:-}"
    if [ -n "$self_path" ] && [ -f "$self_path" ]; then
        if [ "$(realpath "$self_path" 2>/dev/null || echo "$self_path")" != "$SCRIPT_DEST" ]; then
            cp -f "$self_path" "$SCRIPT_DEST"
        fi
    else
        # 通过 bash -c "$(curl ...)" 执行时，从远程仓库保存管理脚本副本
        local raw_urls=(
            "https://raw.githubusercontent.com/${SUOHA_REPO}/main/suoha.sh"
            "https://ghfast.top/https://raw.githubusercontent.com/${SUOHA_REPO}/main/suoha.sh"
        )
        for u in "${raw_urls[@]}"; do
            if curl -fsSL --connect-timeout 8 "$u" -o "$SCRIPT_DEST" 2>/dev/null && [ -s "$SCRIPT_DEST" ]; then
                break
            fi
        done
    fi

    if [ -f "$SCRIPT_DEST" ]; then
        chmod +x "$SCRIPT_DEST"
        ln -sf "$SCRIPT_DEST" "$GLOBAL_CMD"
    fi
}

register_service() {
    if is_alpine; then
        cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run

name="New-Suoha Web Panel"
description="New-Suoha Cloudflare Argo & Xray Web Control Panel"
command="${PANEL_BIN}"
command_args="serve -data-dir ${DATA_DIR}"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"
output_log="/var/log/${SERVICE_NAME}.log"
error_log="/var/log/${SERVICE_NAME}.log"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "/etc/init.d/${SERVICE_NAME}"
        rc-update add "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    else
        cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=New-Suoha Cloudflare Argo & Xray Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DATA_DIR}
ExecStart=${PANEL_BIN} serve -data-dir ${DATA_DIR}
Restart=always
RestartSec=4s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
}

service_status_text() {
    if is_alpine; then
        if rc-service "${SERVICE_NAME}" status >/dev/null 2>&1; then
            echo "running"
        else
            echo "stopped"
        fi
    else
        if systemctl is-active --quiet "${SERVICE_NAME}.service" 2>/dev/null; then
            echo "running"
        else
            echo "stopped"
        fi
    fi
}

service_start() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" start
    else
        systemctl start "${SERVICE_NAME}.service"
    fi
}

service_stop() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" stop >/dev/null 2>&1 || true
    else
        systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
}

service_restart() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" restart
    else
        systemctl restart "${SERVICE_NAME}.service"
    fi
}

do_install() {
    require_root
    ensure_base_deps
    cleanup_legacy_processes
    download_panel_binary
    install_management_script
    register_service

    echo ""
    "$PANEL_BIN" init -data-dir "$DATA_DIR"
    echo ""

    service_restart
    sleep 1
    if [ "$(service_status_text)" = "running" ]; then
        ok "New-Suoha Web 面板常驻服务已启动！后续在终端输入 ${CYAN}suoha${NC} 即可呼出管理菜单。"
    else
        warn "服务启动状态异常，请检查日志。"
    fi
}

do_update() {
    require_root
    ensure_base_deps
    info "正在暂停面板服务以更新二进制内核..."
    service_stop
    download_panel_binary
    install_management_script
    service_start
    ok "面板更新完成，原有配置、订阅路径与优选数据均完整保留！"
}

do_uninstall() {
    require_root
    read -r -p "确定彻底卸载 New-Suoha 面板并清理所有配置与订阅文件吗？[y/N]: " confirm
    if [[ ! "${confirm:-N}" =~ ^[yY]$ ]]; then
        info "已取消卸载。"
        return 0
    fi

    service_stop
    if is_alpine; then
        rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
        rm -f "/etc/init.d/${SERVICE_NAME}" "/var/log/${SERVICE_NAME}.log"
    else
        systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    cleanup_legacy_processes
    rm -rf "$DATA_DIR" /opt/suoha_quick /var/www/suoha_sub
    rm -f "$GLOBAL_CMD" /etc/suoha_sub_port /etc/suoha_sub_uuid /etc/suoha_sub_token
    ok "New-Suoha Web 面板及相关配置数据已全部卸载清理完毕。"
}

reality_submenu() {
    while true; do
        echo ""
        echo "----------------------------------------------------------"
        echo "     VLESS + Reality + XTLS-RPRX-Vision 直连节点管理      "
        echo "----------------------------------------------------------"
        echo " 1. 查看当前 Reality 节点状态与直连链接"
        echo " 2. 一键开启 Reality 直连节点 (默认 Apple SNI: www.apple.com)"
        echo " 3. 关闭 Reality 直连节点"
        echo " 4. 服务器扫描检测可用 SNI 域名 (内置 Apple / 大厂优选池)"
        echo " 5. 服务器扫描同网段 (/24) 邻近可用 SNI 域名"
        echo " 6. 检测并设置其他自定义 SNI 域名"
        echo " 7. 修改 Reality 公网监听端口 (TCP)"
        echo " 8. 重新生成 Reality X25519 密钥对与 ShortID"
        echo " 0. 返回主菜单"
        echo "----------------------------------------------------------"
        read -r -p "请选择操作 [0-8]: " r_choice

        case "${r_choice:-0}" in
            1)
                echo ""
                "$PANEL_BIN" reality -data-dir "$DATA_DIR" status
                ;;
            2)
                read -r -p "输入监听端口 (直接回车保持当前/默认端口): " r_port
                read -r -p "输入伪装 SNI 域名 (直接回车默认使用 www.apple.com): " r_sni
                local args=("on")
                [ -n "${r_port:-}" ] && args+=("$r_port")
                [ -n "${r_sni:-}" ] && args+=("$r_sni")
                if "$PANEL_BIN" reality -data-dir "$DATA_DIR" "${args[@]}"; then
                    service_restart
                    ok "Reality 直连节点已开启并完成服务热同步（系统内部防火墙已自动放行对应 TCP 端口）。"
                fi
                ;;
            3)
                if "$PANEL_BIN" reality -data-dir "$DATA_DIR" off; then
                    service_restart
                    ok "Reality 直连节点已关闭。"
                fi
                ;;
            4)
                "$PANEL_BIN" reality -data-dir "$DATA_DIR" scan preset
                ;;
            5)
                "$PANEL_BIN" reality -data-dir "$DATA_DIR" scan neighbor
                ;;
            6)
                read -r -p "请输入要使用的 SNI 域名 (例如 www.apple.com 或 itunes.apple.com): " custom_sni
                if [ -n "${custom_sni:-}" ]; then
                    "$PANEL_BIN" reality -data-dir "$DATA_DIR" scan "$custom_sni"
                    if "$PANEL_BIN" reality -data-dir "$DATA_DIR" sni "$custom_sni"; then
                        service_restart
                        ok "新 SNI 域名已应用生效。"
                    fi
                fi
                ;;
            7)
                read -r -p "请输入新的 Reality 监听端口号 (1-65535): " new_rport
                if "$PANEL_BIN" reality -data-dir "$DATA_DIR" port "$new_rport"; then
                    service_restart
                    ok "Reality 监听端口已更新并自动放行系统防火墙。"
                fi
                ;;
            8)
                if "$PANEL_BIN" reality -data-dir "$DATA_DIR" rekey; then
                    service_restart
                    ok "Reality 密钥对与 ShortID 已重置，客户端更新订阅即可同步。"
                fi
                ;;
            0)
                return
                ;;
            *)
                warn "请输入有效的编号 [0-8]"
                ;;
        esac
    done
}

firewall_submenu() {
    while true; do
        echo ""
        echo "----------------------------------------------------------"
        echo "          VPS 系统内部防火墙 (UFW) 可视化终端管理         "
        echo "----------------------------------------------------------"
        echo " 1. 查看 UFW 状态、系统监听服务端口检测与规则列表"
        echo " 2. 一键安装 UFW 系统防火墙组件 (apt/apk/dnf/yum)"
        echo " 3. 一键同步放行 SSH + 面板 + 系统中其他运行服务端口"
        echo " 4. 安全启用 UFW 防火墙 (自动预放行 SSH/面板与运行服务端口)"
        echo " 5. 关闭停用 UFW 防火墙 (保留已有规则配置)"
        echo " 6. 手动放行自定义端口 / 端口段 (ALLOW)"
        echo " 7. 拦截封禁指定端口 (DENY)"
        echo " 8. 按规则编号删除指定 UFW 规则"
        echo " 0. 返回主菜单"
        echo "----------------------------------------------------------"
        read -r -p "请选择操作 [0-8]: " fw_choice

        case "${fw_choice:-0}" in
            1)
                echo ""
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" status
                ;;
            2)
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" install
                ;;
            3)
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" sync
                ;;
            4)
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" enable
                ;;
            5)
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" disable
                ;;
            6)
                read -r -p "输入要放行的端口或端口段 (如 443、8080/tcp、10000:20000/udp): " fw_port
                if [ -n "${fw_port:-}" ]; then
                    read -r -p "可选备注说明 (直接回车留空): " fw_cmt
                    if [ -n "${fw_cmt:-}" ]; then
                        "$PANEL_BIN" ufw -data-dir "$DATA_DIR" allow "$fw_port" "$fw_cmt"
                    else
                        "$PANEL_BIN" ufw -data-dir "$DATA_DIR" allow "$fw_port"
                    fi
                fi
                ;;
            7)
                read -r -p "输入要拦截封禁的端口 (如 3306/tcp): " fw_deny_port
                if [ -n "${fw_deny_port:-}" ]; then
                    "$PANEL_BIN" ufw -data-dir "$DATA_DIR" deny "$fw_deny_port"
                fi
                ;;
            8)
                "$PANEL_BIN" ufw -data-dir "$DATA_DIR" status
                read -r -p "输入要删除的规则编号 [数字]: " fw_idx
                if [ -n "${fw_idx:-}" ]; then
                    "$PANEL_BIN" ufw -data-dir "$DATA_DIR" delete "$fw_idx"
                fi
                ;;
            0)
                return
                ;;
            *)
                warn "请输入有效的编号 [0-8]"
                ;;
        esac
    done
}

interactive_menu() {
    require_root
    while true; do
        local st
        st=$(service_status_text)
        local st_badge
        if [ "$st" = "running" ]; then
            st_badge="${GREEN}运行中 (running)${NC}"
        else
            st_badge="${RED}已停止 (stopped)${NC}"
        fi

        echo ""
        echo "=========================================================="
        echo "          New-Suoha Web 管理面板终端运维工具              "
        echo "=========================================================="
        echo -e " 面板服务状态 : ${st_badge}"
        echo "----------------------------------------------------------"
        echo " 1. 查看面板访问地址、订阅链接与客户端命令"
        echo " 2. 重置面板管理员账号与密码"
        echo " 3. 修改面板与订阅共用监听端口"
        echo " 4. 开启 / 关闭 Argo 隧道穿透访问面板后台"
        echo " 5. 管理 VLESS+Reality+Vision 直连节点 (开关/扫描/设置SNI)"
        echo " 6. 管理 VPS 系统内部防火墙 (UFW 开关 / 放行端口 / 规则列表)"
        echo " 7. 重启面板服务"
        echo " 8. 启动面板服务"
        echo " 9. 停止面板服务"
        echo " 10. 更新面板二进制内核 (保留配置)"
        echo " 11. 彻底卸载面板与清理数据"
        echo " 0. 退出"
        echo "=========================================================="
        read -r -p "请选择操作 [0-11]: " choice

        case "${choice:-0}" in
            1)
                echo ""
                "$PANEL_BIN" info -data-dir "$DATA_DIR"
                ;;
            2)
                read -r -p "输入新的管理员用户名 (直接回车保持默认): " new_u
                read -r -p "输入新的登录密码 (直接回车自动随机生成 12 位密码): " new_p
                "$PANEL_BIN" reset-password -data-dir "$DATA_DIR" -user "$new_u" -password "$new_p"
                service_restart
                ok "面板服务已重启，新登录凭据已生效。"
                ;;
            3)
                read -r -p "请输入新的监听端口号 (1-65535): " new_port
                if "$PANEL_BIN" set-port -data-dir "$DATA_DIR" "$new_port"; then
                    service_restart
                    ok "面板已切换至新端口 ${new_port} 并完成重启。"
                fi
                ;;
            4)
                echo "----------------------------------------------------------"
                echo " 1. 一键开启 Argo 临时隧道穿透面板 (自动分配 https://*.trycloudflare.com 地址)"
                echo " 2. 允许通过已有 Argo 隧道访问管理面板 (on)"
                echo " 3. 禁止通过 Argo 隧道访问管理面板，仅保留订阅 (off)"
                echo "----------------------------------------------------------"
                read -r -p "请选择 [1-3, 默认 1]: " argo_choice
                case "${argo_choice:-1}" in
                    1|quick)
                        if "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" quick; then
                            service_restart
                            "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" wait
                        fi
                        ;;
                    2|on)
                        if "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" on; then
                            service_restart
                            ok "Argo 面板穿透权限已开启。"
                        fi
                        ;;
                    3|off)
                        if "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" off; then
                            service_restart
                            ok "已关闭通过 Argo 隧道访问面板后台。"
                        fi
                        ;;
                    *)
                        warn "无效选项"
                        ;;
                esac
                ;;
            5)
                reality_submenu
                ;;
            6)
                firewall_submenu
                ;;
            7)
                service_restart
                ok "面板服务已重启。"
                ;;
            8)
                service_start
                ok "面板服务已启动。"
                ;;
            9)
                service_stop
                warn "面板服务已停止。"
                ;;
            10)
                do_update
                ;;
            11)
                do_uninstall
                exit 0
                ;;
            0)
                exit 0
                ;;
            *)
                warn "请输入有效的菜单编号 [0-11]"
                ;;
        esac
    done
}

main() {
    local subcmd="${1:-}"
    case "$subcmd" in
        install)
            do_install
            ;;
        info | status)
            require_root
            "$PANEL_BIN" info -data-dir "$DATA_DIR"
            ;;
        reset-pwd | reset-password)
            require_root
            shift
            "$PANEL_BIN" reset-password -data-dir "$DATA_DIR" "$@"
            service_restart
            ;;
        port | set-port)
            require_root
            shift
            "$PANEL_BIN" set-port -data-dir "$DATA_DIR" "$@"
            service_restart
            ;;
        argo)
            require_root
            shift
            local a_act="${1:-quick}"
            "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" "$a_act"
            service_restart
            if [ "$a_act" = "quick" ]; then
                "$PANEL_BIN" argo-panel -data-dir "$DATA_DIR" wait
            fi
            ;;
        reality)
            require_root
            shift
            local r_act="${1:-status}"
            "$PANEL_BIN" reality -data-dir "$DATA_DIR" "$@"
            case "$r_act" in
                on|enable|off|disable|sni|set-sni|domain|port|set-port|rekey|rotate)
                    if [ "$(service_status_text)" = "running" ]; then
                        service_restart
                        ok "面板与 Xray 服务已重启同步生效。"
                    fi
                    ;;
            esac
            ;;
        ufw | firewall)
            require_root
            shift
            "$PANEL_BIN" ufw -data-dir "$DATA_DIR" "$@"
            ;;
        start)
            require_root
            service_start
            ;;
        stop)
            require_root
            service_stop
            ;;
        restart)
            require_root
            service_restart
            ;;
        update)
            do_update
            ;;
        uninstall)
            do_uninstall
            ;;
        "")
            if [ ! -x "$PANEL_BIN" ]; then
                do_install
            else
                interactive_menu
            fi
            ;;
        *)
            echo "用法: suoha [install|info|reset-pwd|port <端口>|argo <quick|on|off>|reality <status|on|off|sni|port|rekey|scan>|ufw <status|sync|enable|disable|allow|deny|delete|install>|start|stop|restart|update|uninstall]"
            exit 1
            ;;
    esac
}

main "$@"
