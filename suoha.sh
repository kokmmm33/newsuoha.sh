#!/bin/bash
# onekey suoha
linux_os=("Debian" "Ubuntu" "CentOS" "Fedora" "Alpine")
linux_update=("apt update" "apt update" "yum -y update" "yum -y update" "apk update")
linux_install=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "apk add -f")
n=0
for i in `echo ${linux_os[@]}`
do
    if [ $i == $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') ]
    then
        break
    else
        n=$[$n+1]
    fi
done
if [ $n == 5 ]
then
    echo "当前系统$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2)没有适配"
    echo "默认使用APT包管理器"
    n=0
fi
if [ -z $(type -P unzip) ]
then
    ${linux_update[$n]}
    ${linux_install[$n]} unzip
fi
if [ -z $(type -P curl) ]
then
    ${linux_update[$n]}
    ${linux_install[$n]} curl
fi
if [ -z $(type -P python3) ]
then
    ${linux_update[$n]}
    ${linux_install[$n]} python3
fi
if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') != "Alpine" ]
then
    if [ -z $(type -P systemctl) ]
    then
        ${linux_update[$n]}
        ${linux_install[$n]} systemctl
    fi
fi

function get_server_ip(){
    local ip=""
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
    if [[ -z "$ip" || "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        ip=$(curl -s4 --connect-timeout 2 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | awk -F= '/ip/{print $2}')
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -s4 --connect-timeout 2 https://ipv4.icanhazip.com 2>/dev/null | tr -d '\n\r ')
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -s4 --connect-timeout 2 https://api.ip.sb/ip 2>/dev/null | tr -d '\n\r ')
    fi
    if [ -z "$ip" ]; then
        ip=$(curl -s6 --connect-timeout 2 https://api64.ipify.org 2>/dev/null | tr -d '\n\r ')
    fi
    echo "$ip"
}

function get_server_ipv6(){
    local ip6=""
    ip6=$(curl -s6 --connect-timeout 3 https://api64.ipify.org 2>/dev/null | tr -d '\n\r ')
    if [ -z "$ip6" ]; then
        ip6=$(curl -s6 --connect-timeout 3 https://ipv6.icanhazip.com 2>/dev/null | tr -d '\n\r ')
    fi
    if [ -z "$ip6" ]; then
        ip6=$(curl -s6 --connect-timeout 3 https://speed.cloudflare.com/meta 2>/dev/null | awk -F\" '{print $26}' | grep ":" | tr -d '\n\r ')
    fi
    if [ -z "$ip6" ]; then
        ip6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d/ -f1 | head -n 1 | tr -d '\n\r ')
    fi
    echo "$ip6"
}

function get_or_create_sub_port(){
    local port_file="/etc/suoha_sub_port"
    local port=""
    if [ -f "$port_file" ]; then
        port=$(cat "$port_file" | tr -d '\n\r ')
    fi
    if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
        port=$[$RANDOM%10000+25000]
        echo "$port" > "$port_file"
    fi
    echo "$port"
}

function get_or_create_sub_uuid(){
    local uuid_file="/etc/suoha_sub_uuid"
    local sub_uuid=""
    if [ -f "$uuid_file" ]; then
        sub_uuid=$(cat "$uuid_file" | tr -d '\n\r ')
    fi
    if [[ -z "$sub_uuid" || ! "$sub_uuid" =~ ^[a-fA-F0-9-]+$ ]]; then
        sub_uuid=$(cat /proc/sys/kernel/random/uuid)
        echo "$sub_uuid" > "$uuid_file"
    fi
    echo "$sub_uuid"
}

function get_or_create_sub_token(){
    local token_file="/etc/suoha_sub_token"
    local token=""
    if [ -f "$token_file" ]; then
        token=$(cat "$token_file" | tr -d '\n\r ')
    fi
    if [ -z "$token" ]; then
        token=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 16)
        if [ -z "$token" ]; then
            token="${RANDOM}${RANDOM}${RANDOM}"
        fi
        echo "$token" > "$token_file"
        chmod 600 "$token_file" 2>/dev/null
    fi
    echo "$token"
}

function ensure_sub_server_script(){
    local static_dir="/var/www/suoha_sub"
    mkdir -p "$static_dir" >/dev/null 2>&1
    cat > "${static_dir}/sub_server.py" << 'PYEOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import datetime
import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import sys
import threading
import urllib.parse

STATIC_DIR = "/var/www/suoha_sub"
META_FILE = os.path.join(STATIC_DIR, "meta.json")
PREF_FILE = os.path.join(STATIC_DIR, "preferred_ips.json")
TOKEN_FILE = "/etc/suoha_sub_token"
SUB_UUID_FILE = "/etc/suoha_sub_uuid"

REGEN_LOCK = threading.Lock()


def load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def atomic_write(path, content):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, path)


def get_expected_token(meta):
    try:
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                tok = f.read().strip()
                if tok:
                    return tok
    except Exception:
        pass
    return str(meta.get("sub_token", "")).strip()


def get_sub_uuid(meta):
    try:
        if os.path.exists(SUB_UUID_FILE):
            with open(SUB_UUID_FILE, "r", encoding="utf-8") as f:
                u = f.read().strip()
                if u:
                    return u
    except Exception:
        pass
    return str(meta.get("sub_uuid", "")).strip()


def sanitize_label(text):
    text = re.sub(r"[\r\n\t#\"'\\]+", "", str(text or "")).strip()
    text = re.sub(r"\s+", "_", text)
    return text


def format_host_for_url(host):
    host = str(host or "").strip()
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def build_ip_label(idx, entry):
    raw_label = sanitize_label(entry.get("label", ""))
    if raw_label:
        return raw_label
    parts = [f"优选{idx}"]
    colo = sanitize_label(entry.get("colo", ""))
    latency = sanitize_label(entry.get("latency", ""))
    speed = sanitize_label(entry.get("speed", ""))
    if colo:
        parts.append(colo)
    if latency:
        parts.append(latency)
    if speed:
        parts.append(speed.replace("/s", ""))
    return "-".join(parts)


def regenerate_all():
    with REGEN_LOCK:
        meta = load_json(META_FILE, {})
        if not meta or not meta.get("uuid"):
            return False

        pref_data = load_json(PREF_FILE, {"updated_at": "", "ips": []})
        pref_ips = pref_data.get("ips", [])
        if not isinstance(pref_ips, list):
            pref_ips = []

        uuid = meta["uuid"]
        argo_vl = meta.get("argo_vl", "")
        argo_tr = meta.get("argo_tr", "") or argo_vl
        urlpath_vless = meta.get("urlpath_vless", "")
        urlpath_trojan = meta.get("urlpath_trojan", "")
        node_tag = meta.get("node_tag", "Argo_Node") or "Argo_Node"
        default_label = meta.get("default_label", "默认Argo") or "默认Argo"
        work_dir = meta.get("work_dir", "")
        server_ip = meta.get("server_ip", "") or argo_vl
        sub_port = meta.get("sub_port", 25000)
        sub_uuid = get_sub_uuid(meta)
        sub_token = get_expected_token(meta)

        dynamic_targets = []
        seen_names = set()
        for idx, item in enumerate(pref_ips, 1):
            if not isinstance(item, dict):
                continue
            ip = str(item.get("ip", "")).strip()
            if not ip:
                continue
            try:
                port = int(item.get("port", 443) or 443)
            except Exception:
                port = 443
            if port < 1 or port > 65535:
                port = 443
            label = build_ip_label(idx, item)
            if label in seen_names:
                label = f"{label}-{idx}"
            seen_names.add(label)
            dynamic_targets.append((ip, port, label))

        fallback_opt = [
            ("cf.090227.xyz", 443, "优选cf.090227"),
            ("cloudflare.182682.xyz", 443, "优选182682"),
        ]

        vless_targets = list(dynamic_targets) + [(argo_vl, 443, default_label)] + fallback_opt
        trojan_targets = list(dynamic_targets) + [(argo_tr, 443, default_label)] + fallback_opt

        nodes_lines = []
        proxy_names = []
        clash_lines = [
            "port: 7890",
            "socks-port: 7891",
            "allow-lan: false",
            "mode: rule",
            "log-level: info",
            "proxies:",
        ]

        for host, port, label in vless_targets:
            host_uri = format_host_for_url(host)
            pname = f"{node_tag}-VLESS-{label}-{port}"
            if pname in proxy_names:
                pname = f"{pname}-{len(proxy_names)+1}"
            vless_uri = (
                f"vless://{uuid}@{host_uri}:{port}"
                f"?encryption=none&security=tls&sni={argo_vl}"
                f"&type=ws&host={argo_vl}&path=%2F{urlpath_vless}"
                f"#{pname}"
            )
            nodes_lines.append(vless_uri)
            proxy_names.append(pname)
            clash_lines.extend([
                f'  - name: "{pname}"',
                "    type: vless",
                f'    server: "{host}"',
                f"    port: {port}",
                f"    uuid: {uuid}",
                "    cipher: auto",
                "    tls: true",
                "    udp: true",
                f"    servername: {argo_vl}",
                "    network: ws",
                "    ws-opts:",
                f"      path: /{urlpath_vless}",
                "      headers:",
                f"        Host: {argo_vl}",
            ])

        for host, port, label in trojan_targets:
            host_uri = format_host_for_url(host)
            pname = f"{node_tag}-Trojan-{label}-{port}"
            if pname in proxy_names:
                pname = f"{pname}-{len(proxy_names)+1}"
            trojan_uri = (
                f"trojan://{uuid}@{host_uri}:{port}"
                f"?security=tls&sni={argo_tr}"
                f"&type=ws&host={argo_tr}&path=%2F{urlpath_trojan}"
                f"#{pname}"
            )
            nodes_lines.append(trojan_uri)
            proxy_names.append(pname)
            clash_lines.extend([
                f'  - name: "{pname}"',
                "    type: trojan",
                f'    server: "{host}"',
                f"    port: {port}",
                f"    password: {uuid}",
                "    udp: true",
                f"    sni: {argo_tr}",
                "    network: ws",
                "    ws-opts:",
                f"      path: /{urlpath_trojan}",
                "      headers:",
                f"        Host: {argo_tr}",
            ])

        ss_info = meta.get("ss")
        if isinstance(ss_info, dict) and ss_info.get("ss_link"):
            nodes_lines.append(ss_info["ss_link"])
            proxy_names.append("IPv6-SS-Direct")
            clash_lines.extend([
                '  - name: "IPv6-SS-Direct"',
                "    type: ss",
                f'    server: "{ss_info.get("ipv6_addr", "")}"',
                f'    port: {ss_info.get("ss_port", 30000)}',
                f'    cipher: {ss_info.get("ss_method", "aes-128-gcm")}',
                f'    password: "{ss_info.get("ss_password", "")}"',
                "    udp: true",
            ])

        clash_lines.extend([
            "proxy-groups:",
            "  - name: PROXY",
            "    type: select",
            "    proxies:",
        ])
        for pname in proxy_names:
            clash_lines.append(f'      - "{pname}"')
        clash_lines.extend([
            "rules:",
            "  - MATCH,PROXY",
            "",
        ])

        nodes_content = "\n".join(nodes_lines) + "\n"
        sub_b64 = base64.b64encode(nodes_content.encode("utf-8")).decode("ascii")
        clash_content = "\n".join(clash_lines)

        server_host_url = format_host_for_url(server_ip)
        base_url = f"http://{server_host_url}:{sub_port}"
        sub_path_prefix = f"/{sub_uuid}" if sub_uuid else ""
        sub_online_url = f"{base_url}{sub_path_prefix}/sub.txt"
        clash_online_url = f"{base_url}{sub_path_prefix}/clash.yaml"
        target_static_dir = os.path.join(STATIC_DIR, sub_uuid) if sub_uuid else STATIC_DIR

        updated_at = pref_data.get("updated_at") or "暂未上传 (当前使用默认与公共优选域名)"
        v2ray_content = f"""======================== 一键梭哈 443 TLS 节点列表 ========================
{nodes_content.strip()}

端口替换提示:
443 端口可根据需要改为 CF 其它 TLS 端口: 2053, 2083, 2087, 2096, 8443

======================== 动态优选 IP 状态 ========================
当前动态优选 IP 数量: {len(dynamic_targets)} 个
最近更新时间: {updated_at}
优选列表记录: {PREF_FILE}

======================== 客户端订阅及导入链接 ========================
本机固定订阅服务端口: {sub_port} (已永久保存，重新部署无需重新导入客户端)

1. 通用订阅链接 (支持 v2rayN / NekoBox / Shadowrocket):
{sub_online_url}

2. v2rayN / NekoBox 一键导入协议链接:
sub://{sub_online_url}

3. Clash / Clash.Meta / Mihomo 一键导入配置:
clash://install-config?url={clash_online_url}

4. Clash 在线配置文件直链:
{clash_online_url}

======================== 客户端本地优选 IP 自动上传 ========================
服务端上传地址: {base_url}
专属鉴权 Token: {sub_token} (已永久保存于 /etc/suoha_sub_token)

客户端后台定时测速上传 (默认每 6 小时测速并上传 Top 5 优选 IP):
  Linux / macOS : ./suoha-client -server "{base_url}" -token "{sub_token}"
  Windows (CMD) : suoha-client.exe -server "{base_url}" -token "{sub_token}"

客户端单次立即测速上传 (附加 -once 参数):
  ./suoha-client -server "{base_url}" -token "{sub_token}" -once

持久订阅存储目录: {target_static_dir}/
=====================================================================
"""

        os.makedirs(STATIC_DIR, exist_ok=True)
        os.makedirs(target_static_dir, exist_ok=True)
        atomic_write(os.path.join(STATIC_DIR, "index.html"), "")
        atomic_write(os.path.join(target_static_dir, "index.html"), "")
        atomic_write(os.path.join(target_static_dir, "nodes.txt"), nodes_content)
        atomic_write(os.path.join(target_static_dir, "sub.txt"), sub_b64)
        atomic_write(os.path.join(target_static_dir, "clash.yaml"), clash_content)
        atomic_write(os.path.join(target_static_dir, "v2ray.txt"), v2ray_content)

        if work_dir and os.path.isdir(work_dir) and os.path.abspath(work_dir) != os.path.abspath(target_static_dir):
            for fname in ("nodes.txt", "sub.txt", "clash.yaml", "v2ray.txt"):
                try:
                    shutil.copyfile(
                        os.path.join(target_static_dir, fname),
                        os.path.join(work_dir, fname),
                    )
                except Exception:
                    pass
        return True


def is_valid_host_or_ip(val):
    if not val or len(val) > 253:
        return False
    return bool(re.match(r"^[a-zA-Z0-9.:-]+$", val))


class SubHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def log_message(self, fmt, *args):
        pass

    def _send_json(self, status_code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        meta = load_json(META_FILE, {})
        expected_tok = get_expected_token(meta)
        expected_uuid = get_sub_uuid(meta)
        valid_tokens = {t for t in (expected_tok, expected_uuid) if t}
        if not valid_tokens:
            return False
        auth_hdr = self.headers.get("Authorization", "").strip()
        if auth_hdr.lower().startswith("bearer "):
            provided = auth_hdr[7:].strip()
            if provided in valid_tokens:
                return True
        api_hdr = self.headers.get("X-Api-Token", "").strip()
        if api_hdr and api_hdr in valid_tokens:
            return True
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("token", [""])[0] in valid_tokens:
            return True
        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        req_path = parsed.path

        meta = load_json(META_FILE, {})
        sub_uuid = get_sub_uuid(meta)
        allowed_sub_paths = {}
        if sub_uuid:
            for fname in ("sub.txt", "clash.yaml", "nodes.txt"):
                allowed_sub_paths[f"/{sub_uuid}/{fname}"] = os.path.join(STATIC_DIR, sub_uuid, fname)
        else:
            for fname in ("sub.txt", "clash.yaml", "nodes.txt"):
                allowed_sub_paths[f"/{fname}"] = os.path.join(STATIC_DIR, fname)

        if req_path in allowed_sub_paths:
            fpath = allowed_sub_paths[req_path]
            if not os.path.isfile(fpath):
                regenerate_all()
            if not os.path.isfile(fpath):
                self._send_json(404, {"ok": False, "error": "Subscription file not found"})
                return
            with open(fpath, "rb") as f:
                data = f.read()
            ctype = "text/yaml; charset=utf-8" if req_path.endswith(".yaml") else "text/plain; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
            return

        if req_path == "/api/preferred_ips":
            if not self._check_auth():
                self._send_json(401, {"ok": False, "error": "Unauthorized"})
                return
            pref_data = load_json(PREF_FILE, {"updated_at": "", "ips": []})
            self._send_json(200, {"ok": True, "data": pref_data})
            return

        if req_path == "/health":
            self._send_json(200, {"ok": True})
            return

        self._send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.endswith("/api/update_ips"):
            self._send_json(404, {"ok": False, "error": "Not found"})
            return

        if not self._check_auth():
            self._send_json(401, {"ok": False, "error": "Unauthorized token"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0

        if length <= 0 or length > 1024 * 1024:
            self._send_json(400, {"ok": False, "error": "Invalid payload size"})
            return

        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._send_json(400, {"ok": False, "error": "Invalid JSON body"})
            return

        raw_ips = payload.get("ips") if isinstance(payload, dict) else None
        if not isinstance(raw_ips, list):
            self._send_json(400, {"ok": False, "error": "Field 'ips' must be a list"})
            return

        cleaned_ips = []
        for idx, item in enumerate(raw_ips[:50], 1):
            if isinstance(item, str):
                ip_str = item.strip()
                if is_valid_host_or_ip(ip_str):
                    cleaned_ips.append({
                        "ip": ip_str,
                        "port": 443,
                        "latency": "",
                        "speed": "",
                        "colo": "",
                        "label": f"优选{idx}",
                    })
            elif isinstance(item, dict):
                ip_str = str(item.get("ip", "")).strip()
                if not is_valid_host_or_ip(ip_str):
                    continue
                try:
                    port = int(item.get("port", 443) or 443)
                except Exception:
                    port = 443
                if port < 1 or port > 65535:
                    port = 443
                entry = {
                    "ip": ip_str,
                    "port": port,
                    "latency": sanitize_label(item.get("latency", "")),
                    "speed": sanitize_label(item.get("speed", "")),
                    "colo": sanitize_label(item.get("colo", "")),
                }
                entry["label"] = build_ip_label(len(cleaned_ips) + 1, {
                    **entry,
                    "label": item.get("label", ""),
                })
                cleaned_ips.append(entry)

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pref_data = {
            "updated_at": now_str,
            "ips": cleaned_ips,
        }
        os.makedirs(STATIC_DIR, exist_ok=True)
        atomic_write(PREF_FILE, json.dumps(pref_data, indent=2, ensure_ascii=False))
        regenerated = regenerate_all()

        self._send_json(200, {
            "ok": True,
            "count": len(cleaned_ips),
            "updated_at": now_str,
            "regenerated": regenerated,
        })


class DualStackServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server(port):
    os.makedirs(STATIC_DIR, exist_ok=True)
    regenerate_all()
    try:
        class IPv6DualStackServer(DualStackServer):
            address_family = socket.AF_INET6

            def server_bind(self):
                try:
                    self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except Exception:
                    pass
                super().server_bind()

        httpd = IPv6DualStackServer(("::", port), SubHTTPRequestHandler)
    except Exception:
        httpd = DualStackServer(("0.0.0.0", port), SubHTTPRequestHandler)

    httpd.serve_forever()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--regen":
        regenerate_all()
        sys.exit(0)
    listen_port = int(sys.argv[1]) if len(sys.argv) >= 2 else 25000
    run_server(listen_port)
PYEOF
    chmod +x "${static_dir}/sub_server.py" 2>/dev/null
}

function write_sub_meta(){
    local mode="$1"
    local work_dir="$2"
    local uuid="$3"
    local argo_vl="$4"
    local argo_tr="$5"
    local urlpath_vless="$6"
    local urlpath_trojan="$7"
    local node_tag="$8"
    local default_label="$9"
    local server_ip="${10}"
    local sub_port="${11}"
    local sub_uuid="${12}"
    local sub_token="${13}"

    ensure_sub_server_script
    python3 -c "
import json, os

meta_file = '/var/www/suoha_sub/meta.json'
meta = {
    'mode': '$mode',
    'work_dir': '$work_dir',
    'uuid': '$uuid',
    'argo_vl': '$argo_vl',
    'argo_tr': '$argo_tr',
    'urlpath_vless': '$urlpath_vless',
    'urlpath_trojan': '$urlpath_trojan',
    'node_tag': '$node_tag',
    'default_label': '$default_label',
    'server_ip': '$server_ip',
    'sub_port': int('$sub_port'),
    'sub_uuid': '$sub_uuid',
    'sub_token': '$sub_token',
}
os.makedirs('/var/www/suoha_sub', exist_ok=True)
with open(meta_file, 'w', encoding='utf-8') as f:
    json.dump(meta, f, indent=2, ensure_ascii=False)
"
    python3 /var/www/suoha_sub/sub_server.py --regen
}

function start_sub_server(){
    local web_dir="$1"
    local port="$2"

    ensure_sub_server_script
    pkill -f "http.server $port" >/dev/null 2>&1
    pkill -f "sub_server.py $port" >/dev/null 2>&1
    fuser -k ${port}/tcp >/dev/null 2>&1

    if [ -x "$(command -v python3)" ]; then
        nohup python3 "${web_dir}/sub_server.py" "$port" >/dev/null 2>&1 &
    elif [ -x "$(command -v python)" ]; then
        cd "$web_dir" && nohup python -m SimpleHTTPServer $port >/dev/null 2>&1 &
        cd - >/dev/null 2>&1
    fi
}

function sync_to_static_web(){
    local src_dir="$1"
    local sub_uuid
    sub_uuid=$(get_or_create_sub_uuid)
    local base_dir="/var/www/suoha_sub"
    local static_dir="${base_dir}/${sub_uuid}"
    mkdir -p "$static_dir" >/dev/null 2>&1
    rm -f "${base_dir}/nodes.txt" "${base_dir}/sub.txt" "${base_dir}/clash.yaml" 2>/dev/null
    : > "${base_dir}/index.html" 2>/dev/null
    : > "${static_dir}/index.html" 2>/dev/null
    [ -f "${src_dir}/nodes.txt" ] && cp -f "${src_dir}/nodes.txt" "${static_dir}/nodes.txt" 2>/dev/null
    [ -f "${src_dir}/sub.txt" ] && cp -f "${src_dir}/sub.txt" "${static_dir}/sub.txt" 2>/dev/null
    [ -f "${src_dir}/clash.yaml" ] && cp -f "${src_dir}/clash.yaml" "${static_dir}/clash.yaml" 2>/dev/null
}

function quicktunnel(){
mkdir -p /opt/suoha_quick >/dev/null 2>&1
cd /opt/suoha_quick

# 精确清理旧的后台快速模式进程，严禁使用盲目匹配
if [ -f "/opt/suoha_quick/xray.pid" ]; then
    kill -9 $(cat /opt/suoha_quick/xray.pid) >/dev/null 2>&1
    rm -f /opt/suoha_quick/xray.pid
fi
if [ -f "/opt/suoha_quick/cf_vl.pid" ]; then
    kill -9 $(cat /opt/suoha_quick/cf_vl.pid) >/dev/null 2>&1
    rm -f /opt/suoha_quick/cf_vl.pid
fi
if [ -f "/opt/suoha_quick/cf_tr.pid" ]; then
    kill -9 $(cat /opt/suoha_quick/cf_tr.pid) >/dev/null 2>&1
    rm -f /opt/suoha_quick/cf_tr.pid
fi

rm -rf xray cloudflared-linux xray.zip

case "$(uname -m)" in
    x86_64 | x64 | amd64 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux
    ;;
    i386 | i686 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-32.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux
    ;;
    armv8 | arm64 | aarch64 )
    echo arm64
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux
    ;;
    armv7l )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm32-v7a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o cloudflared-linux
    ;;
    * )
    echo "当前架构$(uname -m)没有适配"
    exit
    ;;
esac
mkdir xray
unzip -d xray xray.zip
chmod +x cloudflared-linux xray/xray
rm -rf xray.zip

uuid=$(cat /proc/sys/kernel/random/uuid)
urlpath_vless="vl-$(echo $uuid | awk -F- '{print $1}')"
urlpath_trojan="tr-$(echo $uuid | awk -F- '{print $1}')"

port_vless=$[$RANDOM+10000]
port_trojan=$[$port_vless+1]

cat>xray/config.json<<EOF
{
    "inbounds": [
        {
            "tag": "vless-in",
            "port": $port_vless,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "decryption": "none",
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$urlpath_vless"
                }
            }
        },
        {
            "tag": "trojan-in",
            "port": $port_trojan,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$uuid"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$urlpath_trojan"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

# 精确记录 Xray PID
/opt/suoha_quick/xray/xray run -config /opt/suoha_quick/xray/config.json >/dev/null 2>&1 &
echo $! > /opt/suoha_quick/xray.pid

# 精确记录 cloudflared 实例 PID
/opt/suoha_quick/cloudflared-linux tunnel --url http://127.0.0.1:$port_vless --no-autoupdate --edge-ip-version $ips --protocol http2 >argo_vless.log 2>&1 &
echo $! > /opt/suoha_quick/cf_vl.pid

/opt/suoha_quick/cloudflared-linux tunnel --url http://127.0.0.1:$port_trojan --no-autoupdate --edge-ip-version $ips --protocol http2 >argo_trojan.log 2>&1 &
echo $! > /opt/suoha_quick/cf_tr.pid

sleep 2

n=0
while true
do
n=$[$n+1]
clear
echo "等待 cloudflare argo 生成双协议专属地址，已等待 $n 秒..."
argo_vl=$(grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare\.com" argo_vless.log | head -n 1 | awk -F// '{print $2}')
argo_tr=$(grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare\.com" argo_trojan.log | head -n 1 | awk -F// '{print $2}')

if [ $n == 20 ]
then
    n=0
    [ -f "/opt/suoha_quick/cf_vl.pid" ] && kill -9 $(cat /opt/suoha_quick/cf_vl.pid) >/dev/null 2>&1
    [ -f "/opt/suoha_quick/cf_tr.pid" ] && kill -9 $(cat /opt/suoha_quick/cf_tr.pid) >/dev/null 2>&1
    rm -rf argo_vless.log argo_trojan.log
    clear
    echo "argo 获取超时，正在重新尝试建立双隧道..."
    /opt/suoha_quick/cloudflared-linux tunnel --url http://127.0.0.1:$port_vless --no-autoupdate --edge-ip-version $ips --protocol http2 >argo_vless.log 2>&1 &
    echo $! > /opt/suoha_quick/cf_vl.pid
    /opt/suoha_quick/cloudflared-linux tunnel --url http://127.0.0.1:$port_trojan --no-autoupdate --edge-ip-version $ips --protocol http2 >argo_trojan.log 2>&1 &
    echo $! > /opt/suoha_quick/cf_tr.pid
    sleep 2
elif [[ -z "$argo_vl" || -z "$argo_tr" ]]
then
    sleep 1
else
    rm -rf argo_vless.log argo_trojan.log
    break
fi
done
clear

node_tag=$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')
if [[ -z "$node_tag" || "$node_tag" == "--" ]]; then
    node_tag="Argo_Node"
fi

server_ip=$(get_server_ip)
if [ -z "$server_ip" ]; then
    server_ip="$argo_vl"
fi

sub_port=$(get_or_create_sub_port)
sub_uuid=$(get_or_create_sub_uuid)
sub_token=$(get_or_create_sub_token)

write_sub_meta "quick" "/opt/suoha_quick" "$uuid" "$argo_vl" "$argo_tr" "$urlpath_vless" "$urlpath_trojan" "$node_tag" "默认Argo" "$server_ip" "$sub_port" "$sub_uuid" "$sub_token"
start_sub_server "/var/www/suoha_sub" "$sub_port"

cat /opt/suoha_quick/v2ray.txt
echo -e "\n信息已经保存在 /opt/suoha_quick/v2ray.txt,再次查看请运行 cat /opt/suoha_quick/v2ray.txt"
}

function install_ipv6_ss(){
    clear
    echo "正在检测机器公网 IPv6 地址..."
    local ipv6_addr
    ipv6_addr=$(get_server_ipv6)

    if [ -z "$ipv6_addr" ]; then
        echo "未检测到可用的公网 IPv6 地址，无法部署 IPv6 直连 SS 节点！"
        read -p "按回车键返回主菜单..."
        return
    fi

    echo "检测到公网 IPv6: $ipv6_addr"

    local xray_dir=""
    local is_installed_mode=0
    local cfg_json=""
    local xray_bin=""

    if [ -f "/opt/suoha/config.json" ]; then
        xray_dir="/opt/suoha"
        is_installed_mode=1
        cfg_json="/opt/suoha/config.json"
        xray_bin="/opt/suoha/xray"
    elif [ -f "/opt/suoha_quick/xray/config.json" ]; then
        xray_dir="/opt/suoha_quick"
        is_installed_mode=0
        cfg_json="/opt/suoha_quick/xray/config.json"
        xray_bin="/opt/suoha_quick/xray/xray"
    else
        echo "未检测到正在运行的 Xray 服务，请先执行【1.梭哈模式】或【2.安装服务】！"
        read -p "按回车键返回主菜单..."
        return
    fi

    local ss_port=$[$RANDOM%10000+30000]
    local ss_password=$(cat /proc/sys/kernel/random/uuid | awk -F- '{print $1$2}')
    local ss_method="aes-128-gcm"

    echo "正在注入 IPv6 Shadowsocks 节点 (端口: $ss_port, 加密: $ss_method)..."

    # 使用 Python 安全操作 JSON，杜绝写入截断
    python3 -c "
import json, sys

cfg_file = '$cfg_json'
try:
    with open(cfg_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 移除已有的 ss-ipv6，保留原本的所有 vless 和 trojan 入站
    data['inbounds'] = [ib for ib in data.get('inbounds', []) if ib.get('tag') != 'ss-ipv6']
    
    ss_ib = {
        'tag': 'ss-ipv6',
        'port': int('$ss_port'),
        'listen': '::',
        'protocol': 'shadowsocks',
        'settings': {
            'method': '$ss_method',
            'password': '$ss_password',
            'network': 'tcp,udp'
        }
    }
    data['inbounds'].append(ss_ib)
    
    with open(cfg_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
except Exception as e:
    sys.exit(1)
"
    if [ $? -ne 0 ]; then
        echo "注入 Xray 配置失败，请检查 python3 环境！"
        read -p "按回车键返回主菜单..."
        return
    fi

    # 只精准重启 Xray 进程，严禁使用盲目 pkill，防止杀掉正在连接的 cloudflared 隧道
    if [ $is_installed_mode -eq 1 ]; then
        if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
        then
            /etc/local.d/xray.start >/dev/null 2>&1
        else
            systemctl restart xray.service >/dev/null 2>&1
        fi
    else
        # 针对梭哈模式，只精准击杀记录的 xray PID，绝不触碰 cloudflared
        if [ -f "/opt/suoha_quick/xray.pid" ]; then
            kill -9 $(cat /opt/suoha_quick/xray.pid) >/dev/null 2>&1
            rm -f /opt/suoha_quick/xray.pid
        else
            kill -9 $(pgrep -f "/opt/suoha_quick/xray/xray") >/dev/null 2>&1
        fi
        nohup $xray_bin run -config $cfg_json >/dev/null 2>&1 &
        echo $! > /opt/suoha_quick/xray.pid
    fi

    local ss_user_info="${ss_method}:${ss_password}"
    local ss_base64
    if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
    then
        ss_base64=$(echo -n "$ss_user_info" | base64 | tr -d '\n')
    else
        ss_base64=$(echo -n "$ss_user_info" | base64 -w 0)
    fi
    local ss_link="ss://${ss_base64}@[${ipv6_addr}]:${ss_port}#IPv6-SS-Direct"

    ensure_sub_server_script
    python3 -c "
import json, os

meta_file = '/var/www/suoha_sub/meta.json'
meta = {}
if os.path.exists(meta_file):
    try:
        with open(meta_file, 'r', encoding='utf-8') as f:
            meta = json.load(f)
    except Exception:
        meta = {}

meta['ss'] = {
    'ipv6_addr': '$ipv6_addr',
    'ss_port': int('$ss_port'),
    'ss_method': '$ss_method',
    'ss_password': '$ss_password',
    'ss_link': '$ss_link',
}
os.makedirs('/var/www/suoha_sub', exist_ok=True)
with open(meta_file, 'w', encoding='utf-8') as f:
    json.dump(meta, f, indent=2, ensure_ascii=False)
"
    python3 /var/www/suoha_sub/sub_server.py --regen

    local sub_port=$(get_or_create_sub_port)
    local sub_uuid=$(get_or_create_sub_uuid)
    local server_ip=$(get_server_ip)
    local sub_online_url="http://${server_ip}:${sub_port}/${sub_uuid}/sub.txt"

    clear
    echo "=========================================================="
    echo "       IPv6 Shadowsocks 直连节点共存部署成功！            "
    echo "=========================================================="
    echo "SS 直连链接:"
    echo "$ss_link"
    echo ""
    echo "原 Argo 临时隧道依然持续运行，所有节点完好无损！"
    echo "客户端直接点击【更新订阅】即可同步获取全部节点："
    echo "订阅地址: ${sub_online_url}"
    echo "=========================================================="
    echo ""
    read -p "按回车键返回主菜单..."
}

function installtunnel(){
mkdir -p /opt/suoha/ >/dev/null 2>&1
cd /opt/suoha
rm -rf xray cloudflared-linux xray.zip

case "$(uname -m)" in
    x86_64 | x64 | amd64 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux
    ;;
    i386 | i686 )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-32.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux
    ;;
    armv8 | arm64 | aarch64 )
    echo arm64
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux
    ;;
    armv7l )
    curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm32-v7a.zip -o xray.zip
    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o cloudflared-linux
    ;;
    * )
    echo "当前架构$(uname -m)没有适配"
    exit
    ;;
esac
mkdir xray
unzip -d xray xray.zip
chmod +x cloudflared-linux xray/xray
mv xray/xray /opt/suoha/
rm -rf xray xray.zip

uuid=$(cat /proc/sys/kernel/random/uuid)
urlpath_vless="vl-$(echo $uuid | awk -F- '{print $1}')"
urlpath_trojan="tr-$(echo $uuid | awk -F- '{print $1}')"
port_vless=$[$RANDOM+10000]
port_trojan=$[$port_vless+1]

cat>/opt/suoha/config.json<<EOF
{
    "inbounds": [
        {
            "tag": "vless-in",
            "port": $port_vless,
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {
                "decryption": "none",
                "clients": [
                    {
                        "id": "$uuid"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$urlpath_vless"
                }
            }
        },
        {
            "tag": "trojan-in",
            "port": $port_trojan,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$uuid"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/$urlpath_trojan"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

clear
echo "复制下面的链接,用浏览器打开并授权需要绑定的域名"
echo "在网页中授权完毕后会继续进行下一步设置"
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel login
clear
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel list >argo.log 2>&1
echo -e "ARGO TUNNEL当前已经绑定的服务如下\n"
sed 1,2d argo.log | awk '{print $2}'
echo -e "\n自定义一个完整二级域名,例如 xxx.example.com"
echo "必须是网页里面绑定授权的域名才生效,不能乱输入"
read -p "输入绑定域名的完整二级域名: " domain
if [ -z "$domain" ]
then
    echo "没有设置域名"
    exit
elif [ $(echo $domain | grep "\." | wc -l) == 0 ]
then
    echo "域名格式不正确"
    exit
fi
name=$(echo $domain | awk -F\. '{print $1}')
if [ $(sed 1,2d argo.log | awk '{print $2}' | grep -w $name | wc -l) == 0 ]
then
    echo "创建TUNNEL $name"
    /opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel create $name >argo.log 2>&1
    echo "TUNNEL $name 创建成功"
else
    echo "TUNNEL $name 已经存在"
    if [ ! -f "/root/.cloudflared/$(sed 1,2d argo.log | awk '{print $1" "$2}' | grep -w $name | awk '{print $1}').json" ]
    then
        echo "/root/.cloudflared/$(sed 1,2d argo.log | awk '{print $1" "$2}' | grep -w $name | awk '{print $1}').json 文件不存在"
        echo "清理TUNNEL $name"
        /opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel cleanup $name >argo.log 2>&1
        echo "删除TUNNEL $name"
        /opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel delete $name >argo.log 2>&1
        echo "重建TUNNEL $name"
        /opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel create $name >argo.log 2>&1
    else
        echo "清理TUNNEL $name"
        /opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel cleanup $name >argo.log 2>&1
    fi
fi
echo "绑定 TUNNEL $name 到域名 $domain"
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel route dns --overwrite-dns $name $domain >argo.log 2>&1
echo "$domain 绑定成功"
tunneluuid=$(cut -d= -f2 argo.log)

node_tag=$(echo $isp | sed -e 's/_/%20/g' -e 's/,/%2C/g')
if [[ -z "$node_tag" || "$node_tag" == "--" ]]; then
    node_tag="Argo_Node"
fi

server_ip=$(get_server_ip)
if [ -z "$server_ip" ]; then
    server_ip="$domain"
fi

sub_port=$(get_or_create_sub_port)
sub_uuid=$(get_or_create_sub_uuid)
sub_token=$(get_or_create_sub_token)

write_sub_meta "installed" "/opt/suoha" "$uuid" "$domain" "$domain" "$urlpath_vless" "$urlpath_trojan" "$node_tag" "自定域名" "$server_ip" "$sub_port" "$sub_uuid" "$sub_token"
start_sub_server "/var/www/suoha_sub" "$sub_port"

rm -rf argo.log

cat>/opt/suoha/config.yaml<<EOF
tunnel: $tunneluuid
credentials-file: /root/.cloudflared/$tunneluuid.json

ingress:
  - hostname: $domain
    path: /$urlpath_vless
    service: http://127.0.0.1:$port_vless
  - hostname: $domain
    path: /$urlpath_trojan
    service: http://127.0.0.1:$port_trojan
  - service: http_status:404
EOF

if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
then
cat>/etc/local.d/cloudflared.start<<EOF
/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/suoha/config.yaml run $name &
EOF
cat>/etc/local.d/xray.start<<EOF
/opt/suoha/xray run -config /opt/suoha/config.json &
EOF
chmod +x /etc/local.d/cloudflared.start /etc/local.d/xray.start
rc-update add local
/etc/local.d/cloudflared.start >/dev/null 2>&1
/etc/local.d/xray.start >/dev/null 2>&1
else
cat>/lib/systemd/system/cloudflared.service<<EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/suoha/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/suoha/config.yaml run $name
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
cat>/lib/systemd/system/xray.service<<EOF
[Unit]
Description=Xray
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/suoha/xray run -config /opt/suoha/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
systemctl enable cloudflared.service >/dev/null 2>&1
systemctl enable xray.service >/dev/null 2>&1
systemctl --system daemon-reload
systemctl start cloudflared.service
systemctl start xray.service
fi

if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
then
cat>/opt/suoha/suoha.sh<<EOF
#!/bin/bash
while true
do
if [ \$(ps -ef | grep cloudflared-linux | grep -v grep | wc -l) == 0 ]
then
    argostatus=stop
else
    argostatus=running
fi
if [ \$(ps -ef | grep xray | grep -v grep | wc -l) == 0 ]
then
    xraystatus=stop
else
    xraystatus=running
fi
echo argo \$argostatus
echo xray \$xraystatus
echo 1.管理TUNNEL
echo 2.启动服务
echo 3.停止服务
echo 4.重启服务
echo 5.卸载服务
echo 6.查看当前订阅与节点链接
echo 0.退出
read -p "请选择菜单(默认0): " menu
if [ -z "\$menu" ]
then
    menu=0
fi
if [ \$menu == 1 ]
then
    clear
    while true
    do
        echo ARGO TUNNEL当前已经绑定的服务如下
        /opt/suoha/cloudflared-linux tunnel list
        echo 1.删除TUNNEL
        echo 0.退出
        read -p "请选择菜单(默认0): " tunneladmin
        if [ -z "\$tunneladmin" ]
        then
            tunneladmin=0
        fi
        if [ \$tunneladmin == 1 ]
        then
            read -p "请输入要删除的TUNNEL NAME: " tunnelname
            echo 断开TUNNEL \$tunnelname
            /opt/suoha/cloudflared-linux tunnel cleanup \$tunnelname
            echo 删除TUNNEL \$tunnelname
            /opt/suoha/cloudflared-linux tunnel delete \$tunnelname
        else
            break
        fi
    done
elif [ \$menu == 2 ]
then
    kill -9 \$(ps -ef | grep xray | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    kill -9 \$(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    /etc/local.d/cloudflared.start >/dev/null 2>&1
    /etc/local.d/xray.start >/dev/null 2>&1
    clear
    sleep 1
elif [ \$menu == 3 ]
then
    kill -9 \$(ps -ef | grep xray | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    kill -9 \$(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    clear
    sleep 2
elif [ \$menu == 4 ]
then
    kill -9 \$(ps -ef | grep xray | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    kill -9 \$(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    /etc/local.d/cloudflared.start >/dev/null 2>&1
    /etc/local.d/xray.start >/dev/null 2>&1
    clear
    sleep 1
elif [ \$menu == 5 ]
then
    kill -9 \$(ps -ef | grep xray | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    kill -9 \$(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print \$1}') >/dev/null 2>&1
    pkill -f "http.server" >/dev/null 2>&1
    pkill -f "sub_server.py" >/dev/null 2>&1
    rm -rf /opt/suoha /opt/suoha_quick /etc/local.d/cloudflared.start /etc/local.d/xray.start /usr/bin/suoha ~/.cloudflared /etc/suoha_sub_port /etc/suoha_sub_uuid /etc/suoha_sub_token /var/www/suoha_sub
    echo 所有服务都卸载完成
    echo 彻底删除授权记录
    echo 请访问 https://dash.cloudflare.com/profile/api-tokens
    echo 删除授权的 Argo Tunnel API Token 即可
    exit
elif [ \$menu == 6 ]
then
    clear
    cat /opt/suoha/v2ray.txt
elif [ \$menu == 0 ]
then
    echo 退出成功
    exit
fi
done
EOF
else
cat>/opt/suoha/suoha.sh<<EOF
#!/bin/bash
clear
while true
do
echo argo \$(systemctl status cloudflared.service | sed -n '3p')
echo xray \$(systemctl status xray.service | sed -n '3p')
echo 1.管理TUNNEL
echo 2.启动服务
echo 3.停止服务
echo 4.重启服务
echo 5.卸载服务
echo 6.查看当前订阅与节点链接
echo 0.退出
read -p "请选择菜单(默认0): " menu
if [ -z "\$menu" ]
then
    menu=0
fi
if [ \$menu == 1 ]
then
    clear
    while true
    do
        echo ARGO TUNNEL当前已经绑定的服务如下
        /opt/suoha/cloudflared-linux tunnel list
        echo 1.删除TUNNEL
        echo 0.退出
        read -p "请选择菜单(默认0): " tunneladmin
        if [ -z "\$tunneladmin" ]
        then
            tunneladmin=0
        fi
        if [ \$tunneladmin == 1 ]
        then
            read -p "请输入要删除的TUNNEL NAME: " tunnelname
            echo 断开TUNNEL \$tunnelname
            /opt/suoha/cloudflared-linux tunnel cleanup \$tunnelname
            echo 删除TUNNEL \$tunnelname
            /opt/suoha/cloudflared-linux tunnel delete \$tunnelname
        else
            break
        fi
    done
elif [ \$menu == 2 ]
then
    systemctl start cloudflared.service
    systemctl start xray.service
    clear
elif [ \$menu == 3 ]
then
    systemctl stop cloudflared.service
    systemctl stop xray.service
    clear
elif [ \$menu == 4 ]
then
    systemctl restart cloudflared.service
    systemctl restart xray.service
    clear
elif [ \$menu == 5 ]
then
    systemctl stop cloudflared.service
    systemctl stop xray.service
    systemctl disable cloudflared.service
    systemctl disable xray.service
    kill -9 \$(ps -ef | grep xray | grep -v grep | awk '{print \$2}') >/dev/null 2>&1
    kill -9 \$(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print \$2}') >/dev/null 2>&1
    pkill -f "http.server" >/dev/null 2>&1
    pkill -f "sub_server.py" >/dev/null 2>&1
    rm -rf /opt/suoha /opt/suoha_quick /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /usr/bin/suoha ~/.cloudflared /etc/suoha_sub_port /etc/suoha_sub_uuid /etc/suoha_sub_token /var/www/suoha_sub
    systemctl --system daemon-reload
    echo 所有服务都卸载完成
    echo 彻底删除授权记录
    echo 请访问 https://dash.cloudflare.com/profile/api-tokens
    echo 删除授权的 Argo Tunnel API Token 即可
    exit
elif [ \$menu == 6 ]
then
    clear
    cat /opt/suoha/v2ray.txt
elif [ \$menu == 0 ]
then
    echo 退出成功
    exit
fi
done
EOF
fi
chmod +x /opt/suoha/suoha.sh
ln -sf /opt/suoha/suoha.sh /usr/bin/suoha
}

clear
echo "梭哈模式不需要自己提供域名,使用CF ARGO QUICK TUNNEL创建快速链接"
echo "梭哈模式在重启或者脚本再次运行后失效,如果需要使用需要再次运行创建"
echo "安装服务模式,需要有CF托管域名,并且需要按照提示手动绑定ARGO服务"
echo "首次绑定ARGO服务后如果不想再次跳转网页绑定"
echo "将已经绑定的系统目录下的 /root/.cloudflared 文件夹以及内容"
echo "拷贝至新系统下同样的目录,会自动跳过登录验证"

echo -e "\n梭哈是一种智慧!!!梭哈!梭哈!梭哈!梭哈!梭哈!梭哈!梭哈...\n"
echo "1.梭哈模式 (自动生成 VLESS+Trojan 443 TLS 优选节点)"
echo "2.安装服务 (自定义域名绑定固定隧道)"
echo "3.卸载服务"
echo "4.清空缓存"
echo "5.额外增加ipv6 ss 共存部署"
echo -e "0.退出脚本\n"
read -p "请选择模式(默认1):" mode
if [ -z "$mode" ]
then
    mode=1
fi
if [ $mode == 1 ]
then
    read -p "请选择argo连接模式IPV4或者IPV6(输入4或6,默认4):" ips
    if [ -z "$ips" ]
    then
        ips=4
    fi
    if [ $ips != 4 ] && [ $ips != 6 ]
    then
        echo "请输入正确的argo连接模式"
        exit
    fi
    isp=$(curl -$ips -s --connect-timeout 2 https://speed.cloudflare.com/meta 2>/dev/null | awk -F\" '{print $26"-"$18"-"$30}' | sed -e 's/ /_/g')
    if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
    then
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
    else
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
    fi
    quicktunnel
elif [ $mode == 2 ]
then
    read -p "请选择argo连接模式IPV4或者IPV6(输入4或6,默认4):" ips
    if [ -z "$ips" ]
    then
        ips=4
    fi
    if [ $ips != 4 ] && [ $ips != 6 ]
    then
        echo "请输入正确的argo连接模式"
        exit
    fi
    isp=$(curl -$ips -s --connect-timeout 2 https://speed.cloudflare.com/meta 2>/dev/null | awk -F\" '{print $26"-"$18"-"$30}' | sed -e 's/ /_/g')
    if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
    then
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        rm -rf /opt/suoha /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /usr/bin/suoha
    else
        systemctl stop cloudflared.service
        systemctl stop xray.service
        systemctl disable cloudflared.service
        systemctl disable xray.service
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        rm -rf /opt/suoha /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /usr/bin/suoha
        systemctl --system daemon-reload
    fi
    installtunnel
    cat /opt/suoha/v2ray.txt
    echo "服务安装完成,管理服务请运行命令 suoha"
elif [ $mode == 3 ]
then
    if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
    then
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        pkill -f "http.server" >/dev/null 2>&1
        pkill -f "sub_server.py" >/dev/null 2>&1
        rm -rf /opt/suoha /opt/suoha_quick /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /usr/bin/suoha /etc/suoha_sub_port /etc/suoha_sub_uuid /etc/suoha_sub_token /var/www/suoha_sub
    else
        systemctl stop cloudflared.service
        systemctl stop xray.service
        systemctl disable cloudflared.service
        systemctl disable xray.service
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        pkill -f "http.server" >/dev/null 2>&1
        pkill -f "sub_server.py" >/dev/null 2>&1
        rm -rf /opt/suoha /opt/suoha_quick /lib/systemd/system/cloudflared.service /lib/systemd/system/xray.service /usr/bin/suoha ~/.cloudflared /etc/suoha_sub_port /etc/suoha_sub_uuid /etc/suoha_sub_token /var/www/suoha_sub
        systemctl --system daemon-reload
    fi
    clear
    echo "所有服务都卸载完成"
    echo "彻底删除授权记录"
    echo "请访问 https://dash.cloudflare.com/profile/api-tokens"
    echo "删除授权的 Argo Tunnel API Token 即可"
elif [ $mode == 4 ]
then
    if [ $(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}') == "Alpine" ]
    then
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $1}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $1}') >/dev/null 2>&1
    else
        kill -9 $(ps -ef | grep xray | grep -v grep | awk '{print $2}') >/dev/null 2>&1
        kill -9 $(ps -ef | grep cloudflared-linux | grep -v grep | awk '{print $2}') >/dev/null 2>&1
    fi
    pkill -f "http.server" >/dev/null 2>&1
    pkill -f "sub_server.py" >/dev/null 2>&1
    rm -rf /opt/suoha_quick/nodes.txt /opt/suoha_quick/sub.txt /opt/suoha_quick/clash.yaml
elif [ $mode == 5 ]
then
    install_ipv6_ss
else
    echo "退出成功"
    exit
fi
