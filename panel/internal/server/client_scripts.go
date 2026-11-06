package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

const defaultReleaseRepo = "kokmmm33/newsuoha.sh"

func requestOriginBaseURL(r *http.Request, fallback string) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return fallback
	}
	scheme := "http"
	if r.TLS != nil ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") ||
		r.Header.Get("Cf-Ray") != "" ||
		strings.HasSuffix(strings.ToLower(strings.Split(host, ":")[0]), ".trycloudflare.com") {
		scheme = "https"
	}
	return scheme + "://" + host
}

// handleClientBootstrapSH serves a POSIX shell bootstrap script for macOS / Linux / OpenWrt.
// It auto-detects OS & CPU architecture, downloads the matching Release binary if missing,
// fixes chmod +x and macOS Gatekeeper quarantine attributes, and runs suoha-client.
func (h *Handler) handleClientBootstrapSH(w http.ResponseWriter, r *http.Request, cfg config.PanelConfig) {
	if !h.checkClientAuth(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized token"})
		return
	}

	rt := h.mgr.RuntimeState()
	fallbackBase := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
	if rt.ServerIP != "" {
		fallbackBase = fmt.Sprintf("http://%s:%d", rt.ServerIP, cfg.ListenPort)
	}
	serverURL := requestOriginBaseURL(r, fallbackBase)

	onceFlag := ""
	qOnce := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("once")))
	if qOnce == "1" || qOnce == "true" || qOnce == "yes" {
		onceFlag = " -once"
	}

	portFlag := ""
	if cfg.Protocols.TLSDefaultPort > 0 && cfg.Protocols.TLSDefaultPort != 443 {
		portFlag = fmt.Sprintf(" -port %d", cfg.Protocols.TLSDefaultPort)
	}

	script := fmt.Sprintf(`#!/bin/sh
set -eu

SERVER_URL=%q
TOKEN=%q
REPO=%q
EXTRA_ARGS="%s%s"

OS_RAW="$(uname -s)"
case "$OS_RAW" in
  Darwin) GOOS="darwin" ;;
  Linux)  GOOS="linux" ;;
  *)
    echo "[错误] 当前系统 ($OS_RAW) 请使用 Windows PowerShell 命令运行" >&2
    exit 1
    ;;
esac

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64|x64)     GOARCH="amd64" ;;
  arm64|aarch64|armv8*) GOARCH="arm64" ;;
  armv7*|armhf)         GOARCH="armv7" ;;
  i386|i686|x86)        GOARCH="386" ;;
  *)
    echo "[错误] 暂未适配该处理器架构: $ARCH_RAW" >&2
    exit 1
    ;;
esac

# Detect Apple Silicon even if Terminal is running under Rosetta 2
if [ "$GOOS" = "darwin" ] && [ "$GOARCH" = "amd64" ]; then
  if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
    GOARCH="arm64"
  fi
fi

ASSET="suoha-client-${GOOS}-${GOARCH}"
WORK_DIR="${HOME}/.suoha-client"
BIN_PATH="${WORK_DIR}/${ASSET}"
mkdir -p "$WORK_DIR"

if [ "${SUOHA_UPDATE:-0}" = "1" ] || [ ! -x "$BIN_PATH" ]; then
  echo "[下载] 正在为当前设备 (${GOOS}/${GOARCH}) 拉取优选测速客户端 ${ASSET} ..."
  RAW_URL="https://github.com/${REPO}/releases/download/latest/${ASSET}"
  TMP_BIN="${BIN_PATH}.tmp"
  DOWNLOADED=0
  for U in "$RAW_URL" "https://ghfast.top/${RAW_URL}" "https://ghproxy.net/${RAW_URL}"; do
    rm -f "$TMP_BIN"
    if command -v curl >/dev/null 2>&1; then
      if curl -fL --connect-timeout 10 --max-time 180 "$U" -o "$TMP_BIN"; then
        if [ -s "$TMP_BIN" ] && [ "$(wc -c < "$TMP_BIN" | tr -d ' ')" -gt 500000 ]; then
          DOWNLOADED=1
          break
        fi
      fi
    elif command -v wget >/dev/null 2>&1; then
      if wget -qO "$TMP_BIN" "$U"; then
        if [ -s "$TMP_BIN" ] && [ "$(wc -c < "$TMP_BIN" | tr -d ' ')" -gt 500000 ]; then
          DOWNLOADED=1
          break
        fi
      fi
    fi
  done

  if [ "$DOWNLOADED" -ne 1 ]; then
    rm -f "$TMP_BIN"
    echo "[错误] 下载 ${ASSET} 失败，请检查本地网络连接" >&2
    exit 1
  fi
  mv -f "$TMP_BIN" "$BIN_PATH"
fi

chmod +x "$BIN_PATH"
if [ "$GOOS" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -cr "$BIN_PATH" 2>/dev/null || xattr -d com.apple.quarantine "$BIN_PATH" 2>/dev/null || true
fi

cd "$WORK_DIR"
echo "[运行] 正在启动本地优选测速: ${BIN_PATH} -server ${SERVER_URL}${EXTRA_ARGS} ..."
exec "$BIN_PATH" -server "$SERVER_URL" -token "$TOKEN" $EXTRA_ARGS "$@"
`, serverURL, cfg.ClientToken, defaultReleaseRepo, portFlag, onceFlag)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

// handleClientBootstrapPS1 serves a Windows PowerShell bootstrap script.
func (h *Handler) handleClientBootstrapPS1(w http.ResponseWriter, r *http.Request, cfg config.PanelConfig) {
	if !h.checkClientAuth(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized token"})
		return
	}

	rt := h.mgr.RuntimeState()
	fallbackBase := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
	if rt.ServerIP != "" {
		fallbackBase = fmt.Sprintf("http://%s:%d", rt.ServerIP, cfg.ListenPort)
	}
	serverURL := requestOriginBaseURL(r, fallbackBase)

	qOnce := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("once")))
	isOnce := qOnce == "1" || qOnce == "true" || qOnce == "yes"

	var extraArgs []string
	if cfg.Protocols.TLSDefaultPort > 0 && cfg.Protocols.TLSDefaultPort != 443 {
		extraArgs = append(extraArgs, "-port", fmt.Sprintf("%d", cfg.Protocols.TLSDefaultPort))
	}
	if isOnce {
		extraArgs = append(extraArgs, "-once")
	}
	psArgsLiteral := ""
	for _, a := range extraArgs {
		psArgsLiteral += fmt.Sprintf(", %q", a)
	}

	script := fmt.Sprintf(`$ErrorActionPreference = "Stop"
$ServerUrl = %q
$Token = %q
$Repo = %q

$Arch = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -match "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -match "ARM64") {
    $Arch = "arm64"
}

$Asset = "suoha-client-windows-$Arch.exe"
$WorkDir = Join-Path $HOME ".suoha-client"
if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
}
$BinPath = Join-Path $WorkDir $Asset

if (-not (Test-Path $BinPath)) {
    Write-Host "[下载] 正在拉取 Windows ($Arch) 优选客户端 $Asset ..." -ForegroundColor Cyan
    $RawUrl = "https://github.com/$Repo/releases/download/latest/$Asset"
    $Urls = @($RawUrl, "https://ghfast.top/$RawUrl", "https://ghproxy.net/$RawUrl")
    $Downloaded = $false
    foreach ($u in $Urls) {
        try {
            Invoke-WebRequest -Uri $u -OutFile $BinPath -UseBasicParsing -TimeoutSec 180
            if ((Get-Item $BinPath).Length -gt 102400) {
                $Downloaded = $true
                break
            }
        } catch {}
    }
    if (-not $Downloaded) {
        throw "下载 $Asset 失败，请检查网络连接"
    }
    Unblock-File -Path $BinPath -ErrorAction SilentlyContinue
}

Set-Location $WorkDir
$CliArgs = @("-server", $ServerUrl, "-token", $Token%s)
Write-Host "[运行] 启动本地优选测速: $BinPath $($CliArgs -join ' ')" -ForegroundColor Green
& $BinPath @CliArgs
`, serverURL, cfg.ClientToken, defaultReleaseRepo, psArgsLiteral)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}
