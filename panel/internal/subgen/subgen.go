package subgen

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

// RuntimeState holds dynamic runtime domains and detected network addresses.
type RuntimeState struct {
	ArgoVL    string `json:"argo_vl"`
	ArgoTR    string `json:"argo_tr"`
	ArgoPanel string `json:"argo_panel"`
	ServerIP  string `json:"server_ip"`
}

// NodeItem represents a single generated proxy node for UI display, copy, and QR rendering.
type NodeItem struct {
	Protocol string `json:"protocol"` // "reality" | "vless" | "trojan" | "ss"
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	URI      string `json:"uri"`
}

// Bundle contains all generated subscription artifacts and metadata URLs.
type Bundle struct {
	Nodes          []NodeItem `json:"nodes"`
	NodesTxt       string     `json:"-"`
	SubBase64      string     `json:"-"`
	ClashYAML      string     `json:"-"`
	V2raySummary   string     `json:"-"`
	DirectBaseURL  string     `json:"direct_base_url"`
	DirectSubURL   string     `json:"direct_sub_url"`
	DirectClashURL string     `json:"direct_clash_url"`
	ArgoBaseURL    string     `json:"argo_base_url,omitempty"`
	ArgoSubURL     string     `json:"argo_sub_url,omitempty"`
	ArgoClashURL   string     `json:"argo_clash_url,omitempty"`
}

type targetEndpoint struct {
	Host  string
	Port  int
	Label string
}

// FormatHostForURL wraps raw IPv6 literals in brackets while leaving IPv4/domains intact.
func FormatHostForURL(host string) string {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// Generate builds the complete subscription bundle from PanelConfig, PreferredStore, and RuntimeState.
func Generate(cfg config.PanelConfig, pref config.PreferredStore, rt RuntimeState) Bundle {
	proto := cfg.Protocols
	nodeTag := config.SanitizeLabel(proto.NodeTag)
	if nodeTag == "" {
		nodeTag = "Argo_Node"
	}

	defaultPort := proto.TLSDefaultPort
	if defaultPort < 1 || defaultPort > 65535 {
		defaultPort = 443
	}

	defaultLabel := "默认Argo"
	if cfg.Tunnel.Mode == "token" {
		defaultLabel = "固定域名"
	}

	// 1. Build dynamic preferred IP targets
	var dynamicTargets []targetEndpoint
	seenLabels := make(map[string]bool)
	for idx, item := range pref.IPs {
		ip := strings.TrimSpace(item.IP)
		if !config.IsValidHostOrIP(ip) {
			continue
		}
		port := item.Port
		if port < 1 || port > 65535 {
			port = defaultPort
		}
		lbl := config.BuildIPLabel(idx+1, item)
		if seenLabels[lbl] {
			lbl = fmt.Sprintf("%s-%d", lbl, idx+1)
		}
		seenLabels[lbl] = true
		dynamicTargets = append(dynamicTargets, targetEndpoint{
			Host:  ip,
			Port:  port,
			Label: lbl,
		})
	}

	// 2. Build fallback preferred domain targets
	var fallbackTargets []targetEndpoint
	for _, fb := range cfg.FallbackDomains {
		if !fb.Enabled {
			continue
		}
		host := strings.TrimSpace(fb.Host)
		if !config.IsValidHostOrIP(host) {
			continue
		}
		port := fb.Port
		if port < 1 || port > 65535 {
			port = defaultPort
		}
		lbl := config.SanitizeLabel(fb.Label)
		if lbl == "" {
			lbl = "优选-" + host
		}
		fallbackTargets = append(fallbackTargets, targetEndpoint{
			Host:  host,
			Port:  port,
			Label: lbl,
		})
	}

	argoVL := strings.TrimSpace(rt.ArgoVL)
	argoTR := strings.TrimSpace(rt.ArgoTR)
	if argoTR == "" {
		argoTR = argoVL
	}

	var nodes []NodeItem
	var nodesLines []string
	var proxyNames []string
	usedNames := make(map[string]bool)

	uniqueName := func(base string) string {
		if !usedNames[base] {
			usedNames[base] = true
			return base
		}
		n := fmt.Sprintf("%s-%d", base, len(proxyNames)+1)
		usedNames[n] = true
		return n
	}

	var proxyLines []string

	// VLESS + Reality + XTLS-RPRX-Vision direct node
	realityHost := resolveDirectHost(proto, rt)
	if proto.RealityEnabled && realityHost != "" {
		pubKey := strings.TrimSpace(proto.RealityPublicKey)
		if pubKey == "" && strings.TrimSpace(proto.RealityPrivateKey) != "" {
			_, pubKey, _ = config.DeriveRealityPublicKey(proto.RealityPrivateKey)
		}
		if pubKey != "" {
			rPort := proto.RealityPort
			if rPort < 1 || rPort > 65535 {
				rPort = 24443
			}
			sni := config.SanitizeRealitySNI(proto.RealitySNI)
			fp := config.SanitizeRealityFingerprint(proto.RealityFingerprint)
			shortID := config.SanitizeRealityShortID(proto.RealityShortID)
			hostURI := FormatHostForURL(realityHost)
			pname := uniqueName(fmt.Sprintf("%s-Reality-直连-%d", nodeTag, rPort))

			uri := fmt.Sprintf(
				"vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp&headerType=none#%s",
				proto.UUID, hostURI, rPort, sni, fp, url.QueryEscape(pubKey), shortID, url.PathEscape(pname),
			)
			nodes = append(nodes, NodeItem{
				Protocol: "reality",
				Name:     pname,
				Host:     realityHost,
				Port:     rPort,
				URI:      uri,
			})
			nodesLines = append(nodesLines, uri)
			proxyNames = append(proxyNames, pname)
			proxyLines = append(proxyLines,
				fmt.Sprintf("  - name: %s", yamlQuote(pname)),
				"    type: vless",
				fmt.Sprintf("    server: %s", yamlQuote(cleanRawHost(realityHost))),
				fmt.Sprintf("    port: %d", rPort),
				fmt.Sprintf("    uuid: %s", yamlQuote(proto.UUID)),
				"    network: tcp",
				"    tls: true",
				"    udp: true",
				"    flow: xtls-rprx-vision",
				fmt.Sprintf("    servername: %s", yamlQuote(sni)),
				fmt.Sprintf("    client-fingerprint: %s", yamlQuote(fp)),
				"    reality-opts:",
				fmt.Sprintf("      public-key: %s", yamlQuote(pubKey)),
				fmt.Sprintf("      short-id: %s", yamlQuote(shortID)),
			)
		}
	}

	// VLESS-WS nodes (only emitted if VLESS is enabled AND tunnel domain is ready)
	if proto.VLESSEnabled && argoVL != "" {
		vlTargets := make([]targetEndpoint, 0, len(dynamicTargets)+1+len(fallbackTargets))
		vlTargets = append(vlTargets, dynamicTargets...)
		vlTargets = append(vlTargets, targetEndpoint{Host: argoVL, Port: defaultPort, Label: defaultLabel})
		vlTargets = append(vlTargets, fallbackTargets...)

		escapedPath := url.PathEscape(proto.VLESSPath)
		for _, t := range vlTargets {
			hostURI := FormatHostForURL(t.Host)
			pname := uniqueName(fmt.Sprintf("%s-VLESS-%s-%d", nodeTag, t.Label, t.Port))
			uri := fmt.Sprintf(
				"vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%%2F%s#%s",
				proto.UUID, hostURI, t.Port, argoVL, argoVL, escapedPath, url.PathEscape(pname),
			)
			nodes = append(nodes, NodeItem{
				Protocol: "vless",
				Name:     pname,
				Host:     t.Host,
				Port:     t.Port,
				URI:      uri,
			})
			nodesLines = append(nodesLines, uri)
			proxyNames = append(proxyNames, pname)
			proxyLines = append(proxyLines,
				fmt.Sprintf("  - name: %s", yamlQuote(pname)),
				"    type: vless",
				fmt.Sprintf("    server: %s", yamlQuote(cleanRawHost(t.Host))),
				fmt.Sprintf("    port: %d", t.Port),
				fmt.Sprintf("    uuid: %s", yamlQuote(proto.UUID)),
				"    cipher: auto",
				"    tls: true",
				"    udp: true",
				"    client-fingerprint: chrome",
				fmt.Sprintf("    servername: %s", yamlQuote(argoVL)),
				"    network: ws",
				"    ws-opts:",
				fmt.Sprintf("      path: %s", yamlQuote("/"+proto.VLESSPath)),
				"      headers:",
				fmt.Sprintf("        Host: %s", yamlQuote(argoVL)),
			)
		}
	}

	// Trojan-WS nodes (only emitted if Trojan is enabled AND tunnel domain is ready)
	if proto.TrojanEnabled && argoTR != "" {
		trTargets := make([]targetEndpoint, 0, len(dynamicTargets)+1+len(fallbackTargets))
		trTargets = append(trTargets, dynamicTargets...)
		trTargets = append(trTargets, targetEndpoint{Host: argoTR, Port: defaultPort, Label: defaultLabel})
		trTargets = append(trTargets, fallbackTargets...)

		escapedPath := url.PathEscape(proto.TrojanPath)
		for _, t := range trTargets {
			hostURI := FormatHostForURL(t.Host)
			pname := uniqueName(fmt.Sprintf("%s-Trojan-%s-%d", nodeTag, t.Label, t.Port))
			uri := fmt.Sprintf(
				"trojan://%s@%s:%d?security=tls&sni=%s&type=ws&host=%s&path=%%2F%s#%s",
				proto.UUID, hostURI, t.Port, argoTR, argoTR, escapedPath, url.PathEscape(pname),
			)
			nodes = append(nodes, NodeItem{
				Protocol: "trojan",
				Name:     pname,
				Host:     t.Host,
				Port:     t.Port,
				URI:      uri,
			})
			nodesLines = append(nodesLines, uri)
			proxyNames = append(proxyNames, pname)
			proxyLines = append(proxyLines,
				fmt.Sprintf("  - name: %s", yamlQuote(pname)),
				"    type: trojan",
				fmt.Sprintf("    server: %s", yamlQuote(cleanRawHost(t.Host))),
				fmt.Sprintf("    port: %d", t.Port),
				fmt.Sprintf("    password: %s", yamlQuote(proto.UUID)),
				"    udp: true",
				"    client-fingerprint: chrome",
				fmt.Sprintf("    sni: %s", yamlQuote(argoTR)),
				"    network: ws",
				"    ws-opts:",
				fmt.Sprintf("      path: %s", yamlQuote("/"+proto.TrojanPath)),
				"      headers:",
				fmt.Sprintf("        Host: %s", yamlQuote(argoTR)),
			)
		}
	}

	// IPv6 Shadowsocks direct node
	ipv6Clean := cleanRawHost(proto.IPv6Addr)
	if proto.IPv6SSEnabled && ipv6Clean != "" {
		pname := uniqueName("IPv6-SS-Direct")
		userInfo := fmt.Sprintf("%s:%s", proto.SSMethod, proto.SSPassword)
		ssB64 := base64.StdEncoding.EncodeToString([]byte(userInfo))
		ssURI := fmt.Sprintf("ss://%s@[%s]:%d#%s", ssB64, ipv6Clean, proto.SSPort, pname)
		nodes = append(nodes, NodeItem{
			Protocol: "ss",
			Name:     pname,
			Host:     ipv6Clean,
			Port:     proto.SSPort,
			URI:      ssURI,
		})
		nodesLines = append(nodesLines, ssURI)
		proxyNames = append(proxyNames, pname)
		proxyLines = append(proxyLines,
			fmt.Sprintf("  - name: %s", yamlQuote(pname)),
			"    type: ss",
			fmt.Sprintf("    server: %s", yamlQuote(ipv6Clean)),
			fmt.Sprintf("    port: %d", proto.SSPort),
			fmt.Sprintf("    cipher: %s", yamlQuote(proto.SSMethod)),
			fmt.Sprintf("    password: %s", yamlQuote(proto.SSPassword)),
			"    udp: true",
		)
	}

	var nodesContent string
	if len(nodesLines) > 0 {
		nodesContent = strings.Join(nodesLines, "\n") + "\n"
	}
	subB64 := base64.StdEncoding.EncodeToString([]byte(nodesContent))
	clashContent := buildClashYAML(proxyLines, proxyNames, cfg, rt)

	// Subscription URLs
	serverHost := strings.TrimSpace(proto.ServerHostOverride)
	if serverHost == "" {
		serverHost = strings.TrimSpace(rt.ServerIP)
	}
	if serverHost == "" {
		serverHost = "127.0.0.1"
	}
	directBase := fmt.Sprintf("http://%s:%d", FormatHostForURL(serverHost), cfg.ListenPort)
	directSub := fmt.Sprintf("%s/%s/sub.txt", directBase, cfg.SubUUID)
	directClash := fmt.Sprintf("%s/%s/clash.yaml", directBase, cfg.SubUUID)

	var argoBase, argoSub, argoClash string
	if ap := strings.TrimSpace(rt.ArgoPanel); ap != "" {
		argoBase = "https://" + ap
		argoSub = fmt.Sprintf("%s/%s/sub.txt", argoBase, cfg.SubUUID)
		argoClash = fmt.Sprintf("%s/%s/clash.yaml", argoBase, cfg.SubUUID)
	}

	updatedAt := pref.UpdatedAt
	if updatedAt == "" {
		updatedAt = "暂未上传 (当前使用默认与公共优选域名)"
	}

	summary := fmt.Sprintf(`======================== New-Suoha 节点与订阅信息 ========================
%s
======================== 动态优选 IP 状态 ========================
当前动态优选 IP 数量: %d 个
最近更新时间: %s

======================== 客户端订阅及导入链接 ========================
直连通用订阅 (v2rayN / NekoBox / Shadowrocket):
  %s
Clash / Mihomo 智能分流配置 (内置 .mrs 规则集 / AUTO 测速 / 防 DNS 泄露):
  %s
`, strings.TrimSpace(nodesContent), len(dynamicTargets), updatedAt, directSub, directClash)

	if argoSub != "" {
		summary += fmt.Sprintf(`
Argo 免端口 HTTPS 通用订阅:
  %s
Argo 免端口 HTTPS Clash / Mihomo 智能分流配置:
  %s
`, argoSub, argoClash)
	}

	uploadTarget := directBase
	if argoBase != "" {
		uploadTarget = argoBase
	}
	summary += fmt.Sprintf(`
======================== 本地优选客户端 (suoha-client) ========================
Mac/Linux 一键立即测速 : sh -c "$(curl -fsSL '%s/api/client.sh?token=%s&once=1')"
Mac/Linux 后台定时测速 : sh -c "$(curl -fsSL '%s/api/client.sh?token=%s')"
Windows 一键立即测速   : powershell -ExecutionPolicy Bypass -Command "irm '%s/api/client.ps1?token=%s&once=1' | iex"
==========================================================================
`, uploadTarget, cfg.ClientToken, uploadTarget, cfg.ClientToken, uploadTarget, cfg.ClientToken)

	return Bundle{
		Nodes:          nodes,
		NodesTxt:       nodesContent,
		SubBase64:      subB64,
		ClashYAML:      clashContent,
		V2raySummary:   summary,
		DirectBaseURL:  directBase,
		DirectSubURL:   directSub,
		DirectClashURL: directClash,
		ArgoBaseURL:    argoBase,
		ArgoSubURL:     argoSub,
		ArgoClashURL:   argoClash,
	}
}

// WriteStaticFiles atomically persists generated subscription files to dataDir (and legacy /var/www/suoha_sub if enabled).
func WriteStaticFiles(store *config.Store, bundle Bundle) error {
	cfg := store.GetConfig()
	subDir := filepath.Join(store.DataDir(), "sub", cfg.SubUUID)
	if err := writeSubDir(subDir, bundle); err != nil {
		return err
	}
	_ = config.AtomicWriteFile(filepath.Join(store.DataDir(), "v2ray.txt"), []byte(bundle.V2raySummary), 0644)

	if store.SyncLegacyEnabled() && store.Legacy().WebDir != "" {
		legacySubDir := filepath.Join(store.Legacy().WebDir, cfg.SubUUID)
		_ = os.MkdirAll(store.Legacy().WebDir, 0755)
		_ = config.AtomicWriteFile(filepath.Join(store.Legacy().WebDir, "index.html"), []byte(""), 0644)
		_ = writeSubDir(legacySubDir, bundle)
	}
	return nil
}

func writeSubDir(dir string, bundle Bundle) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := config.AtomicWriteFile(filepath.Join(dir, "index.html"), []byte(""), 0644); err != nil {
		return err
	}
	if err := config.AtomicWriteFile(filepath.Join(dir, "nodes.txt"), []byte(bundle.NodesTxt), 0644); err != nil {
		return err
	}
	if err := config.AtomicWriteFile(filepath.Join(dir, "sub.txt"), []byte(bundle.SubBase64), 0644); err != nil {
		return err
	}
	if err := config.AtomicWriteFile(filepath.Join(dir, "clash.yaml"), []byte(bundle.ClashYAML), 0644); err != nil {
		return err
	}
	return config.AtomicWriteFile(filepath.Join(dir, "v2ray.txt"), []byte(bundle.V2raySummary), 0644)
}

func cleanRawHost(h string) string {
	h = strings.TrimSpace(h)
	return strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
}

func resolveDirectHost(proto config.ProtocolConfig, rt RuntimeState) string {
	if override := cleanRawHost(proto.ServerHostOverride); override != "" && config.IsValidHostOrIP(override) {
		return override
	}
	for _, cand := range []string{rt.ServerIP, proto.IPv6Addr} {
		h := cleanRawHost(cand)
		if h == "" || strings.EqualFold(h, "localhost") || !config.IsValidHostOrIP(h) {
			continue
		}
		if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
			continue
		}
		return h
	}
	return ""
}

func yamlQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}
