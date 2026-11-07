package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/firewall"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/subgen"
)

var tryCloudflareRe = regexp.MustCompile(`https://([a-zA-Z0-9.-]+\.trycloudflare\.com)`)

// StatusSnapshot reports live process and tunnel states for the Web UI.
type StatusSnapshot struct {
	XrayRunning   bool   `json:"xray_running"`
	XrayError     string `json:"xray_error,omitempty"`
	TunnelRunning bool   `json:"tunnel_running"`
	TunnelState   string `json:"tunnel_state"` // "stopped" | "starting" | "running" | "error"
	TunnelError   string `json:"tunnel_error,omitempty"`
	RealityActive bool   `json:"reality_active"`
	IPv6SSActive  bool   `json:"ipv6_ss_active"`
	ArgoVL        string `json:"argo_vl"`
	ArgoTR        string `json:"argo_tr"`
	ArgoPanel     string `json:"argo_panel"`
	ServerIP      string `json:"server_ip"`
	DetectedIPv6  string `json:"detected_ipv6"`
}

// Manager supervises Xray and cloudflared child processes, handles self-healing, and regenerates subscriptions on domain updates.
type Manager struct {
	store  *config.Store
	logs   *RingLog
	onSync func()

	mu           sync.RWMutex
	serverIP     string
	detectedIPv6 string

	xrayCancel  context.CancelFunc
	xrayRunning bool
	xrayErr     string

	tunCancel  context.CancelFunc
	tunRunning bool
	tunState   string
	tunErr     string
	argoVL     string
	argoTR     string
	argoPanel  string
}

func NewManager(store *config.Store, logs *RingLog, onSync func()) *Manager {
	return &Manager{
		store:    store,
		logs:     logs,
		onSync:   onSync,
		tunState: "stopped",
	}
}

func (m *Manager) Logs() *RingLog {
	return m.logs
}

// InitNetworkAndAutostart probes server IP/IPv6 in background and starts Xray/Tunnel if enabled in persisted config.
func (m *Manager) InitNetworkAndAutostart() {
	netInfo := DetectNetwork()
	cfg := m.store.GetConfig()

	m.mu.Lock()
	m.serverIP = netInfo.ServerIP
	m.detectedIPv6 = netInfo.IPv6Addr
	m.mu.Unlock()

	// Populate default NodeTag and IPv6Addr if not yet customized
	_, _ = m.store.UpdateConfig(func(draft *config.PanelConfig) error {
		if (draft.Protocols.NodeTag == "" || draft.Protocols.NodeTag == "Argo_Node") && netInfo.NodeTag != "" && netInfo.NodeTag != "Argo_Node" {
			draft.Protocols.NodeTag = netInfo.NodeTag
		}
		if draft.Protocols.IPv6Addr == "" && netInfo.IPv6Addr != "" {
			draft.Protocols.IPv6Addr = netInfo.IPv6Addr
		}
		return nil
	})
	cfg = m.store.GetConfig()
	if synced := firewall.SyncPanelPorts(context.Background(), cfg, false); len(synced) > 0 {
		m.logs.Add("panel", "系统防火墙已自动同步放行端口: "+strings.Join(synced, ", "))
	}

	m.triggerSync()

	// If any protocol is active and tunnel/direct node was previously enabled, auto-start Xray
	if cfg.Tunnel.Enabled || cfg.Protocols.IPv6SSEnabled || cfg.Protocols.RealityEnabled {
		go func() {
			if err := m.ReloadXray(); err != nil {
				m.logs.Add("panel", fmt.Sprintf("启动 Xray 失败: %v", err))
			}
		}()
	}
	if cfg.Tunnel.Enabled {
		go func() {
			if err := m.RestartTunnel(); err != nil {
				m.logs.Add("panel", fmt.Sprintf("启动 Argo 隧道失败: %v", err))
			}
		}()
	} else if cfg.Tunnel.PanelQuickTunnel {
		go func() {
			_ = m.RestartTunnel()
		}()
	}
}

// RefreshNetwork re-detects public IPv4/IPv6/ISP tag on user request.
func (m *Manager) RefreshNetwork() NetworkInfo {
	info := DetectNetwork()
	m.mu.Lock()
	if info.ServerIP != "" {
		m.serverIP = info.ServerIP
	}
	if info.IPv6Addr != "" {
		m.detectedIPv6 = info.IPv6Addr
	}
	m.mu.Unlock()
	m.triggerSync()
	return info
}

// ScanRealitySNI scans preset, neighbor /24, or custom Reality SNI domains from this server.
func (m *Manager) ScanRealitySNI(ctx context.Context, mode string, customDomains []string) RealityScanReport {
	m.mu.RLock()
	srvIP := m.serverIP
	m.mu.RUnlock()
	return ScanRealityDomains(ctx, RealityScanOptions{
		Mode:          mode,
		CustomDomains: customDomains,
		ServerIP:      srvIP,
	})
}

func (m *Manager) Status() StatusSnapshot {
	cfg := m.store.GetConfig()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return StatusSnapshot{
		XrayRunning:   m.xrayRunning,
		XrayError:     m.xrayErr,
		TunnelRunning: m.tunRunning,
		TunnelState:   m.tunState,
		TunnelError:   m.tunErr,
		RealityActive: m.xrayRunning && cfg.Protocols.RealityEnabled,
		IPv6SSActive:  m.xrayRunning && cfg.Protocols.IPv6SSEnabled && strings.TrimSpace(cfg.Protocols.IPv6Addr) != "",
		ArgoVL:        m.argoVL,
		ArgoTR:        m.argoTR,
		ArgoPanel:     m.argoPanel,
		ServerIP:      m.serverIP,
		DetectedIPv6:  m.detectedIPv6,
	}
}

func (m *Manager) RuntimeState() subgen.RuntimeState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return subgen.RuntimeState{
		ArgoVL:    m.argoVL,
		ArgoTR:    m.argoTR,
		ArgoPanel: m.argoPanel,
		ServerIP:  m.serverIP,
	}
}

// Shutdown stops all managed child processes cleanly.
func (m *Manager) Shutdown() {
	m.StopTunnel()
	m.StopXray()
}

// StopXray terminates the supervised Xray process.
func (m *Manager) StopXray() {
	m.mu.Lock()
	cancel := m.xrayCancel
	m.xrayCancel = nil
	m.xrayRunning = false
	m.xrayErr = ""
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.logs.Add("panel", "Xray 服务已停止")
}

// ReloadXray regenerates xray_config.json and restarts only Xray without disturbing active cloudflared tunnels.
func (m *Manager) ReloadXray() error {
	cfg := m.store.GetConfig()
	proto := cfg.Protocols

	if !proto.VLESSEnabled && !proto.TrojanEnabled && !proto.IPv6SSEnabled && !proto.RealityEnabled {
		m.StopXray()
		m.triggerSync()
		return nil
	}

	// If IPv6 SS is enabled and IPv6Addr is empty, attempt auto-detect
	if proto.IPv6SSEnabled && strings.TrimSpace(proto.IPv6Addr) == "" {
		v6 := DetectPublicIPv6()
		if v6 == "" {
			return fmt.Errorf("未检测到可用的公网 IPv6 地址，无法启用 IPv6 Shadowsocks 直连节点")
		}
		var err error
		cfg, err = m.store.UpdateConfig(func(draft *config.PanelConfig) error {
			draft.Protocols.IPv6Addr = v6
			return nil
		})
		if err != nil {
			return err
		}
		proto = cfg.Protocols
	}

	if proto.RealityEnabled || proto.IPv6SSEnabled {
		if synced := firewall.SyncPanelPorts(context.Background(), cfg, false); len(synced) > 0 {
			m.logs.Add("panel", "系统防火墙已自动同步放行端口: "+strings.Join(synced, ", "))
		}
	}

	cfgPath, err := m.writeXrayConfig(proto)
	if err != nil {
		return err
	}

	xrayBin, err := EnsureXrayBinary(m.store.DataDir(), m.logs)
	if err != nil {
		m.mu.Lock()
		m.xrayErr = err.Error()
		m.xrayRunning = false
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	if m.xrayCancel != nil {
		m.xrayCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.xrayCancel = cancel
	m.xrayErr = ""
	m.mu.Unlock()

	go m.superviseXrayLoop(ctx, xrayBin, cfgPath)
	m.triggerSync()
	return nil
}

// BuildXrayConfig constructs the Xray-core JSON configuration map for all enabled protocols.
func BuildXrayConfig(proto config.ProtocolConfig) map[string]any {
	var inbounds []map[string]any

	if proto.VLESSEnabled {
		inbounds = append(inbounds, map[string]any{
			"tag":      "vless-in",
			"port":     proto.VLESSLocalPort,
			"listen":   "127.0.0.1",
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients": []map[string]any{
					{"id": proto.UUID},
				},
			},
			"streamSettings": map[string]any{
				"network": "ws",
				"wsSettings": map[string]any{
					"path": "/" + proto.VLESSPath,
				},
			},
		})
	}

	if proto.TrojanEnabled {
		inbounds = append(inbounds, map[string]any{
			"tag":      "trojan-in",
			"port":     proto.TrojanLocalPort,
			"listen":   "127.0.0.1",
			"protocol": "trojan",
			"settings": map[string]any{
				"clients": []map[string]any{
					{"password": proto.UUID},
				},
			},
			"streamSettings": map[string]any{
				"network": "ws",
				"wsSettings": map[string]any{
					"path": "/" + proto.TrojanPath,
				},
			},
		})
	}

	if proto.RealityEnabled && strings.TrimSpace(proto.RealityPrivateKey) != "" {
		sni := config.SanitizeRealitySNI(proto.RealitySNI)
		shortID := config.SanitizeRealityShortID(proto.RealityShortID)
		inbounds = append(inbounds, map[string]any{
			"tag":      "vless-reality-in",
			"port":     proto.RealityPort,
			"listen":   bestPublicListenAddr(),
			"protocol": "vless",
			"settings": map[string]any{
				"decryption": "none",
				"clients": []map[string]any{
					{
						"id":   proto.UUID,
						"flow": "xtls-rprx-vision",
					},
				},
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"show":        false,
					"dest":        fmt.Sprintf("%s:443", sni),
					"xver":        0,
					"serverNames": []string{sni},
					"privateKey":  proto.RealityPrivateKey,
					"shortIds":    []string{shortID},
				},
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
				"routeOnly":    true,
			},
		})
	}

	if proto.IPv6SSEnabled && strings.TrimSpace(proto.IPv6Addr) != "" {
		inbounds = append(inbounds, map[string]any{
			"tag":      "ss-ipv6",
			"port":     proto.SSPort,
			"listen":   "::",
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"method":   proto.SSMethod,
				"password": proto.SSPassword,
				"network":  "tcp,udp",
			},
		})
	}

	return map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
	}
}

func (m *Manager) writeXrayConfig(proto config.ProtocolConfig) (string, error) {
	xrayDoc := BuildXrayConfig(proto)
	raw, err := json.MarshalIndent(xrayDoc, "", "  ")
	if err != nil {
		return "", err
	}
	cfgPath := filepath.Join(m.store.DataDir(), "runtime", "xray_config.json")
	if err := config.AtomicWriteFile(cfgPath, raw, 0600); err != nil {
		return "", err
	}
	return cfgPath, nil
}

func bestPublicListenAddr() string {
	ln, err := net.Listen("tcp", "[::]:0")
	if err == nil {
		_ = ln.Close()
		return "::"
	}
	return "0.0.0.0"
}

func (m *Manager) superviseXrayLoop(ctx context.Context, xrayBin, cfgPath string) {
	for {
		if ctx.Err() != nil {
			return
		}
		cmd := exec.CommandContext(ctx, xrayBin, "run", "-config", cfgPath)
		cmd.Dir = filepath.Dir(xrayBin)
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			m.mu.Lock()
			m.xrayRunning = false
			m.xrayErr = err.Error()
			m.mu.Unlock()
			m.logs.Add("xray", fmt.Sprintf("启动失败: %v", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(4 * time.Second):
				continue
			}
		}

		m.mu.Lock()
		m.xrayRunning = true
		m.xrayErr = ""
		m.mu.Unlock()
		m.logs.Add("xray", fmt.Sprintf("Xray 进程已启动 (PID %d)", cmd.Process.Pid))

		go streamLinesToLog(stdout, "xray", m.logs, nil)
		go streamLinesToLog(stderr, "xray", m.logs, nil)

		err := cmd.Wait()
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		m.xrayRunning = false
		if err != nil {
			m.xrayErr = err.Error()
		}
		m.mu.Unlock()
		m.logs.Add("xray", fmt.Sprintf("Xray 意外退出 (%v)，3 秒后自动重启...", err))

		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// StopTunnel stops all supervised cloudflared instances and clears ephemeral domains.
func (m *Manager) StopTunnel() {
	m.mu.Lock()
	cancel := m.tunCancel
	m.tunCancel = nil
	m.tunRunning = false
	m.tunState = "stopped"
	m.tunErr = ""
	m.argoVL = ""
	m.argoTR = ""
	m.argoPanel = ""
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	m.logs.Add("panel", "Argo 隧道服务已停止")
	m.triggerSync()
}

// RestartTunnel starts or restarts cloudflared according to current TunnelConfig, also ensuring Xray is running when needed.
func (m *Manager) RestartTunnel() error {
	cfg := m.store.GetConfig()
	tun := cfg.Tunnel

	if !tun.Enabled && !tun.PanelQuickTunnel {
		m.StopTunnel()
		return nil
	}

	if tun.Enabled && tun.Mode == "token" {
		if strings.TrimSpace(tun.CFToken) == "" {
			return fmt.Errorf("请填写 Cloudflare Zero Trust Tunnel Token")
		}
		if strings.TrimSpace(tun.CustomDomain) == "" {
			return fmt.Errorf("请填写在 Cloudflare 后台绑定的节点域名 (如 sub.example.com)")
		}
	}

	// Ensure Xray is started if main node tunnel is enabled
	if tun.Enabled {
		m.mu.RLock()
		xRun := m.xrayRunning
		m.mu.RUnlock()
		if !xRun {
			if err := m.ReloadXray(); err != nil {
				return fmt.Errorf("启动前置 Xray 失败: %w", err)
			}
		}
	}

	cfBin, err := EnsureCloudflaredBinary(m.store.DataDir(), m.logs)
	if err != nil {
		m.mu.Lock()
		m.tunState = "error"
		m.tunErr = err.Error()
		m.tunRunning = false
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	if m.tunCancel != nil {
		m.tunCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.tunCancel = cancel
	m.tunRunning = false
	m.tunState = "starting"
	m.tunErr = ""
	m.argoVL = ""
	m.argoTR = ""
	m.argoPanel = ""
	m.mu.Unlock()

	edgeVer := tun.EdgeIPVersion
	if edgeVer != "6" {
		edgeVer = "4"
	}

	if !tun.Enabled && tun.PanelQuickTunnel {
		// Only auxiliary panel/subscription quick tunnel
		localURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
		go m.superviseQuickTunnel(ctx, cfBin, edgeVer, localURL, "panel-only")
		m.triggerSync()
		return nil
	}

	if tun.Mode == "token" {
		domain := strings.TrimSpace(tun.CustomDomain)
		m.mu.Lock()
		m.argoVL = domain
		m.argoTR = domain
		m.argoPanel = domain
		m.mu.Unlock()

		go m.superviseTokenTunnel(ctx, cfBin, edgeVer, strings.TrimSpace(tun.CFToken), domain)
		if tun.PanelQuickTunnel {
			localURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
			go m.superviseQuickTunnel(ctx, cfBin, edgeVer, localURL, "panel-aux")
		}
		m.triggerSync()
		return nil
	}

	// Quick Tunnel mode ("quick")
	if tun.QuickTopology == "dual" {
		if cfg.Protocols.VLESSEnabled {
			u := fmt.Sprintf("http://127.0.0.1:%d", cfg.Protocols.VLESSLocalPort)
			go m.superviseQuickTunnel(ctx, cfBin, edgeVer, u, "vless")
		}
		if cfg.Protocols.TrojanEnabled {
			u := fmt.Sprintf("http://127.0.0.1:%d", cfg.Protocols.TrojanLocalPort)
			go m.superviseQuickTunnel(ctx, cfBin, edgeVer, u, "trojan")
		}
		if tun.PanelQuickTunnel {
			u := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
			go m.superviseQuickTunnel(ctx, cfBin, edgeVer, u, "panel-aux")
		}
	} else {
		// Unified Quick Tunnel -> points directly to Go unified gateway port (carries /vl-xxx, /tr-xxx, /<sub_uuid>/*, and optional /)
		localURL := fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
		go m.superviseQuickTunnel(ctx, cfBin, edgeVer, localURL, "unified")
	}

	m.triggerSync()
	return nil
}

func (m *Manager) superviseQuickTunnel(ctx context.Context, cfBin, edgeVer, targetURL, role string) {
	args := []string{
		"tunnel",
		"--url", targetURL,
		"--no-autoupdate",
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
	}

	for {
		if ctx.Err() != nil {
			return
		}
		m.logs.Add("cloudflared", fmt.Sprintf("[%s] 正在建立 Quick Tunnel -> %s ...", role, targetURL))
		cmd := exec.CommandContext(ctx, cfBin, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			m.mu.Lock()
			m.tunErr = err.Error()
			m.tunState = "error"
			m.mu.Unlock()
			m.logs.Add("cloudflared", fmt.Sprintf("[%s] 启动失败: %v", role, err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		onLine := func(line string) {
			matches := tryCloudflareRe.FindStringSubmatch(line)
			if len(matches) < 2 {
				return
			}
			domain := matches[1]
			changed := false

			m.mu.Lock()
			switch role {
			case "unified":
				if m.argoVL != domain || m.argoTR != domain || m.argoPanel != domain {
					m.argoVL = domain
					m.argoTR = domain
					m.argoPanel = domain
					changed = true
				}
			case "vless":
				if m.argoVL != domain {
					m.argoVL = domain
					changed = true
				}
			case "trojan":
				if m.argoTR != domain {
					m.argoTR = domain
					changed = true
				}
			case "panel-only", "panel-aux":
				if m.argoPanel != domain {
					m.argoPanel = domain
					changed = true
				}
			}
			m.tunRunning = true
			m.tunState = "running"
			m.tunErr = ""
			m.mu.Unlock()

			if changed {
				m.logs.Add("cloudflared", fmt.Sprintf("[%s] Quick Tunnel 域名已就绪: https://%s (订阅已自动同步更新)", role, domain))
				m.triggerSync()
			}
		}

		go streamLinesToLog(stdout, "cloudflared", m.logs, onLine)
		go streamLinesToLog(stderr, "cloudflared", m.logs, onLine)

		err := cmd.Wait()
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		if role == "unified" {
			m.tunRunning = false
			m.tunState = "starting"
		}
		if err != nil {
			m.tunErr = err.Error()
		}
		m.mu.Unlock()
		m.logs.Add("cloudflared", fmt.Sprintf("[%s] 隧道连接中断 (%v)，4 秒后自动重建自愈...", role, err))

		select {
		case <-ctx.Done():
			return
		case <-time.After(4 * time.Second):
		}
	}
}

func (m *Manager) superviseTokenTunnel(ctx context.Context, cfBin, edgeVer, token, domain string) {
	args := []string{
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"--no-autoupdate",
		"run",
		"--token", token,
	}

	for {
		if ctx.Err() != nil {
			return
		}
		m.logs.Add("cloudflared", fmt.Sprintf("[ZeroTrust] 正在连接固定隧道 (%s) ...", domain))
		cmd := exec.CommandContext(ctx, cfBin, args...)
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			m.mu.Lock()
			m.tunRunning = false
			m.tunState = "error"
			m.tunErr = err.Error()
			m.mu.Unlock()
			m.logs.Add("cloudflared", fmt.Sprintf("[ZeroTrust] 启动失败: %v", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				continue
			}
		}

		m.mu.Lock()
		m.tunRunning = true
		m.tunState = "running"
		m.tunErr = ""
		m.mu.Unlock()
		m.triggerSync()

		onLine := func(line string) {
			if strings.Contains(line, "Registered tunnel connection") {
				m.mu.Lock()
				m.tunRunning = true
				m.tunState = "running"
				m.tunErr = ""
				m.mu.Unlock()
			}
		}

		go streamLinesToLog(stdout, "cloudflared", m.logs, onLine)
		go streamLinesToLog(stderr, "cloudflared", m.logs, onLine)

		err := cmd.Wait()
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		m.tunRunning = false
		m.tunState = "starting"
		if err != nil {
			m.tunErr = err.Error()
		}
		m.mu.Unlock()
		m.logs.Add("cloudflared", fmt.Sprintf("[ZeroTrust] 隧道连接断开 (%v)，4 秒后自动重连...", err))

		select {
		case <-ctx.Done():
			return
		case <-time.After(4 * time.Second):
		}
	}
}

func (m *Manager) triggerSync() {
	if m.onSync != nil {
		m.onSync()
	}
}

func streamLinesToLog(r io.Reader, source string, logs *RingLog, hook func(string)) {
	if r == nil {
		return
	}
	sc := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 256*1024)
	for sc.Scan() {
		line := sc.Text()
		if hook != nil {
			hook(line)
		}
		logs.Add(source, line)
	}
}
