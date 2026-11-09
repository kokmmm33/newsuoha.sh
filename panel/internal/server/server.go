package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/firewall"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/proxy"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/subgen"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/supervisor"
)

// PortSwitchFunc validates and hot-switches the active TCP listener to newPort.
type PortSwitchFunc func(newPort int) error

// Handler is the unified HTTP gateway serving WebSocket node proxy, subscriptions, client API, and the embedded Web Panel.
type Handler struct {
	store      *config.Store
	mgr        *supervisor.Manager
	wsProxy    *proxy.WSDispatcher
	sessions   *SessionManager
	limiter    *LoginLimiter
	webStatic  http.Handler
	switchPort PortSwitchFunc
}

func NewHandler(store *config.Store, mgr *supervisor.Manager, webFS fs.FS, switchPort PortSwitchFunc) (*Handler, error) {
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	return &Handler{
		store:      store,
		mgr:        mgr,
		wsProxy:    proxy.NewWSDispatcher(store),
		sessions:   NewSessionManager(),
		limiter:    NewLoginLimiter(),
		webStatic:  http.FileServer(http.FS(subFS)),
		switchPort: switchPort,
	}, nil
}

// SyncStaticSubscriptions regenerates on-disk subscription files from current state.
func (h *Handler) SyncStaticSubscriptions() {
	cfg := h.store.GetConfig()
	pref := h.store.GetPreferred()
	rt := h.mgr.RuntimeState()
	bundle := subgen.Generate(cfg, pref, rt)
	_ = subgen.WriteStaticFiles(h.store, bundle)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. WebSocket / HTTP reverse proxy for VLESS-WS and Trojan-WS paths
	if h.wsProxy.TryServe(w, r) {
		return
	}

	reqPath := r.URL.Path

	// 2. Lightweight health check
	if reqPath == "/health" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	// 3. Subscription files (/<SubUUID>/{sub.txt, clash.yaml, nodes.txt})
	cfg := h.store.GetConfig()
	subPrefix := "/" + cfg.SubUUID + "/"
	if r.Method == http.MethodGet && strings.HasPrefix(reqPath, subPrefix) {
		fname := strings.TrimPrefix(reqPath, subPrefix)
		h.serveSubscriptionFile(w, r, fname, cfg)
		return
	}

	// 4. suoha-client APIs (/api/preferred_ips, /api/update_ips, /api/client.sh, /api/client.ps1)
	if reqPath == "/api/preferred_ips" && r.Method == http.MethodGet {
		h.handleGetPreferredIPs(w, r, cfg)
		return
	}
	if reqPath == "/api/client.sh" && r.Method == http.MethodGet {
		h.handleClientBootstrapSH(w, r, cfg)
		return
	}
	if reqPath == "/api/client.ps1" && r.Method == http.MethodGet {
		h.handleClientBootstrapPS1(w, r, cfg)
		return
	}
	if strings.HasSuffix(reqPath, "/api/update_ips") && r.Method == http.MethodPost {
		h.handleClientUpdateIPs(w, r, cfg)
		return
	}

	// 5. Security guard for Argo Tunnel access when AllowArgoPanel is disabled
	if !cfg.AllowArgoPanel && h.isViaArgoTunnel(r, cfg) {
		http.NotFound(w, r)
		return
	}

	// 6. Admin authentication endpoints
	if reqPath == "/api/admin/session" && r.Method == http.MethodGet {
		user, ok := h.sessions.Validate(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"authenticated": ok,
			"username":      user,
		})
		return
	}
	if reqPath == "/api/admin/login" && r.Method == http.MethodPost {
		h.handleAdminLogin(w, r, cfg)
		return
	}
	if reqPath == "/api/admin/logout" && r.Method == http.MethodPost {
		h.handleAdminLogout(w, r)
		return
	}

	// 7. Protected Admin APIs (/api/admin/*)
	if strings.HasPrefix(reqPath, "/api/admin/") {
		if _, ok := h.sessions.Validate(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "登录状态已过期，请重新登录"})
			return
		}
		h.serveAdminAPI(w, r)
		return
	}

	// 8. Embedded SPA frontend static assets (/, /style.css, /app.js, /qrcode.js)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "Method not allowed"})
		return
	}
	if reqPath == "/" || reqPath == "/index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	h.webStatic.ServeHTTP(w, r)
}

func (h *Handler) isViaArgoTunnel(r *http.Request, cfg config.PanelConfig) bool {
	if !isLoopbackRemote(r.RemoteAddr) {
		return false
	}
	if r.Header.Get("Cf-Ray") != "" || r.Header.Get("Cf-Connecting-Ip") != "" {
		return true
	}
	host := strings.ToLower(strings.Split(r.Host, ":")[0])
	if strings.HasSuffix(host, ".trycloudflare.com") {
		return true
	}
	if cd := strings.ToLower(strings.TrimSpace(cfg.Tunnel.CustomDomain)); cd != "" && host == cd {
		return true
	}
	return false
}

func (h *Handler) checkClientAuth(r *http.Request, cfg config.PanelConfig) bool {
	if _, ok := h.sessions.Validate(r); ok {
		return true
	}
	valid := map[string]bool{}
	if cfg.ClientToken != "" {
		valid[cfg.ClientToken] = true
	}
	if cfg.SubUUID != "" {
		valid[cfg.SubUUID] = true
	}
	if len(valid) == 0 {
		return false
	}
	authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHdr), "bearer ") {
		if valid[strings.TrimSpace(authHdr[7:])] {
			return true
		}
	}
	if apiHdr := strings.TrimSpace(r.Header.Get("X-Api-Token")); apiHdr != "" && valid[apiHdr] {
		return true
	}
	if tok := strings.TrimSpace(r.URL.Query().Get("token")); tok != "" && valid[tok] {
		return true
	}
	return false
}

func (h *Handler) serveSubscriptionFile(w http.ResponseWriter, r *http.Request, fname string, cfg config.PanelConfig) {
	if fname != "sub.txt" && fname != "clash.yaml" && fname != "nodes.txt" {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "Subscription file not found"})
		return
	}
	pref := h.store.GetPreferred()
	rt := h.mgr.RuntimeState()
	bundle := subgen.Generate(cfg, pref, rt)
	_ = subgen.WriteStaticFiles(h.store, bundle)

	served := bundle.ForUserAgent(r.Header.Get("User-Agent"))

	var body []byte
	contentType := "text/plain; charset=utf-8"
	switch fname {
	case "sub.txt":
		body = []byte(served.SubBase64)
	case "nodes.txt":
		body = []byte(served.NodesTxt)
	case "clash.yaml":
		body = []byte(served.ClashYAML)
		contentType = "text/yaml; charset=utf-8"
	}

	titleB64 := base64.StdEncoding.EncodeToString([]byte("New-Suoha"))
	w.Header().Set("Profile-Title", "base64:"+titleB64)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Vary", "User-Agent")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (h *Handler) handleGetPreferredIPs(w http.ResponseWriter, r *http.Request, cfg config.PanelConfig) {
	if !h.checkClientAuth(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized"})
		return
	}
	pref := h.store.GetPreferred()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": pref})
}

func (h *Handler) handleClientUpdateIPs(w http.ResponseWriter, r *http.Request, cfg config.PanelConfig) {
	if !h.checkClientAuth(r, cfg) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Unauthorized token"})
		return
	}

	var payload struct {
		IPs []json.RawMessage `json:"ips"`
	}
	if err := decodeJSONBody(r, &payload, 1024*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid JSON body"})
		return
	}
	if payload.IPs == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Field 'ips' must be a list"})
		return
	}

	var parsed []config.PreferredIP
	for idx, raw := range payload.IPs {
		if idx >= 100 {
			break
		}
		var strItem string
		if json.Unmarshal(raw, &strItem) == nil {
			parsed = append(parsed, config.PreferredIP{
				IP:    strings.TrimSpace(strItem),
				Port:  443,
				Label: fmt.Sprintf("优选%d", idx+1),
			})
			continue
		}
		var objItem config.PreferredIP
		if json.Unmarshal(raw, &objItem) == nil {
			parsed = append(parsed, objItem)
		}
	}

	pref, err := h.store.SetPreferredIPs(parsed, "client")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.SyncStaticSubscriptions()
	h.mgr.Logs().Add("panel", fmt.Sprintf("收到客户端优选 IP 上报: 共生效 %d 个节点", len(pref.IPs)))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"count":       len(pref.IPs),
		"updated_at":  pref.UpdatedAt,
		"regenerated": true,
	})
}

func (h *Handler) handleAdminLogin(w http.ResponseWriter, r *http.Request, cfg config.PanelConfig) {
	ip := clientIPFromRequest(r)
	if allowed, msg := h.limiter.CheckAllowed(ip); !allowed {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": msg})
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSONBody(r, &req, 16*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式无效"})
		return
	}

	if strings.TrimSpace(req.Username) != cfg.AdminUser || !config.VerifyPassword(req.Password, cfg.AdminPassHash) {
		h.limiter.RecordFailure(ip)
		h.mgr.Logs().Add("panel", fmt.Sprintf("管理员登录失败 (来源 IP: %s)", ip))
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "用户名或密码错误"})
		return
	}

	h.limiter.Reset(ip)
	sid := h.sessions.Create(cfg.AdminUser)
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	h.mgr.Logs().Add("panel", fmt.Sprintf("管理员 %s 登录成功 (来源 IP: %s)", cfg.AdminUser, ip))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": cfg.AdminUser,
	})
}

func (h *Handler) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	h.sessions.DeleteRequestSession(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) serveAdminAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/admin/overview" && r.Method == http.MethodGet:
		h.handleOverview(w, r)
	case r.URL.Path == "/api/admin/tunnel/apply" && r.Method == http.MethodPost:
		h.handleTunnelApply(w, r)
	case r.URL.Path == "/api/admin/tunnel/oauth/status" && r.Method == http.MethodGet:
		h.handleTunnelOAuthStatus(w, r)
	case r.URL.Path == "/api/admin/tunnel/oauth/start" && r.Method == http.MethodPost:
		h.handleTunnelOAuthStart(w, r)
	case r.URL.Path == "/api/admin/tunnel/oauth/cancel" && r.Method == http.MethodPost:
		h.handleTunnelOAuthCancel(w, r)
	case r.URL.Path == "/api/admin/service/action" && r.Method == http.MethodPost:
		h.handleServiceAction(w, r)
	case r.URL.Path == "/api/admin/protocols/apply" && r.Method == http.MethodPost:
		h.handleProtocolsApply(w, r)
	case r.URL.Path == "/api/admin/reality/scan" && r.Method == http.MethodPost:
		h.handleRealityScan(w, r)
	case r.URL.Path == "/api/admin/network/detect" && r.Method == http.MethodPost:
		info := h.mgr.RefreshNetwork()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "network": info})
	case r.URL.Path == "/api/admin/preferred/save" && r.Method == http.MethodPost:
		h.handlePreferredSave(w, r)
	case r.URL.Path == "/api/admin/preferred/fallbacks" && r.Method == http.MethodPost:
		h.handleFallbacksSave(w, r)
	case r.URL.Path == "/api/admin/rotate" && r.Method == http.MethodPost:
		h.handleRotateCredential(w, r)
	case r.URL.Path == "/api/admin/settings" && r.Method == http.MethodPost:
		h.handleSettingsSave(w, r)
	case r.URL.Path == "/api/admin/firewall/status" && r.Method == http.MethodGet:
		h.handleFirewallStatus(w, r)
	case r.URL.Path == "/api/admin/firewall/action" && r.Method == http.MethodPost:
		h.handleFirewallAction(w, r)
	case r.URL.Path == "/api/admin/firewall/rule/add" && r.Method == http.MethodPost:
		h.handleFirewallRuleAdd(w, r)
	case r.URL.Path == "/api/admin/firewall/rule/delete" && r.Method == http.MethodPost:
		h.handleFirewallRuleDelete(w, r)
	case r.URL.Path == "/api/admin/logs" && r.Method == http.MethodGet:
		src := r.URL.Query().Get("source")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"logs": h.mgr.Logs().List(src, 200),
		})
	case r.URL.Path == "/api/admin/logs/clear" && r.Method == http.MethodPost:
		h.mgr.Logs().Clear()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "Unknown admin endpoint"})
	}
}

func (h *Handler) handleOverview(w http.ResponseWriter, _ *http.Request) {
	cfg := h.store.GetConfig()
	pref := h.store.GetPreferred()
	st := h.mgr.Status()
	oauthSt := h.mgr.OAuthStatus()
	rt := h.mgr.RuntimeState()
	bundle := subgen.Generate(cfg, pref, rt)

	// Determine recommended server URL for suoha-client:
	// Prefer permanent endpoints (Fixed Named/Token custom domain HTTPS, or Direct HTTP IP:Port)
	// so daemon clients survive Quick Tunnel rotations; fall back to Quick Tunnel HTTPS on NAT hosts.
	clientServer := bundle.DirectBaseURL
	if (cfg.Tunnel.Mode == "token" || cfg.Tunnel.Mode == "named") && bundle.ArgoBaseURL != "" {
		clientServer = bundle.ArgoBaseURL
	} else if rt.ServerIP == "" && bundle.ArgoBaseURL != "" {
		clientServer = bundle.ArgoBaseURL
	}

	// Sanitize password hash from JSON response
	cfgSafe := cfg
	cfgSafe.AdminPassHash = ""

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"config":        cfgSafe,
		"status":        st,
		"oauth":         oauthSt,
		"preferred":     pref,
		"subscription":  bundle,
		"local_gateway": fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort),
		"client_helper": map[string]string{
			"release_repo":     defaultReleaseRepo,
			"server_url":       clientServer,
			"direct_url":       bundle.DirectBaseURL,
			"argo_url":         bundle.ArgoBaseURL,
			"token":            cfg.ClientToken,
			"tls_port":         fmt.Sprintf("%d", cfg.Protocols.TLSDefaultPort),
			"auto_unix_once":   fmt.Sprintf(`sh -c "$(curl -fsSL '%s/api/client.sh?token=%s&once=1')"`, clientServer, cfg.ClientToken),
			"auto_unix_daemon": fmt.Sprintf(`sh -c "$(curl -fsSL '%s/api/client.sh?token=%s')"`, clientServer, cfg.ClientToken),
			"auto_win_once":    fmt.Sprintf(`powershell -ExecutionPolicy Bypass -Command "irm '%s/api/client.ps1?token=%s&once=1' | iex"`, clientServer, cfg.ClientToken),
			"auto_win_daemon":  fmt.Sprintf(`powershell -ExecutionPolicy Bypass -Command "irm '%s/api/client.ps1?token=%s' | iex"`, clientServer, cfg.ClientToken),
		},
	})
}

func (h *Handler) handleTunnelOAuthStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"oauth": h.mgr.OAuthStatus(),
	})
}

func (h *Handler) handleTunnelOAuthStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EdgeIPVersion string `json:"edge_ip_version"`
	}
	_ = decodeJSONBody(r, &req, 4*1024)
	edgeVer := strings.TrimSpace(req.EdgeIPVersion)
	if edgeVer == "" {
		edgeVer = h.store.GetConfig().Tunnel.EdgeIPVersion
	}
	st, err := h.mgr.StartOAuthLogin(edgeVer)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"oauth": st,
	})
}

func (h *Handler) handleTunnelOAuthCancel(w http.ResponseWriter, _ *http.Request) {
	h.mgr.CancelOAuthLogin()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"oauth": h.mgr.OAuthStatus(),
	})
}

func (h *Handler) handleTunnelApply(w http.ResponseWriter, r *http.Request) {
	var req config.TunnelConfig
	if err := decodeJSONBody(r, &req, 64*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "无效的隧道参数"})
		return
	}

	oldCfg := h.store.GetConfig()
	if strings.TrimSpace(req.NamedTunnelName) == "" {
		req.NamedTunnelName = oldCfg.Tunnel.NamedTunnelName
	}
	if strings.TrimSpace(req.NamedTunnelUUID) == "" {
		req.NamedTunnelUUID = oldCfg.Tunnel.NamedTunnelUUID
	}
	if req.Mode != "token" && strings.TrimSpace(req.CFToken) == "" {
		req.CFToken = oldCfg.Tunnel.CFToken
	}

	if req.Enabled && req.Mode == "token" {
		if strings.TrimSpace(req.CFToken) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "固定隧道模式需要填写 Cloudflare Tunnel Token"})
			return
		}
		if strings.TrimSpace(req.CustomDomain) == "" || !strings.Contains(req.CustomDomain, ".") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请填写完整的二级域名 (如 sub.example.com)"})
			return
		}
	}

	if req.Enabled && req.Mode == "named" {
		domain := config.ExtractRealityDomain(req.CustomDomain)
		if !config.IsValidRealityDomain(domain) || strings.HasSuffix(strings.ToLower(domain), ".trycloudflare.com") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请填写要绑定的完整二级域名 (例如 sub.example.com)"})
			return
		}
		provRes, err := h.mgr.ProvisionNamedTunnel(r.Context(), domain, req.EdgeIPVersion)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		req.CustomDomain = provRes.Domain
		req.NamedTunnelName = provRes.TunnelName
		req.NamedTunnelUUID = provRes.TunnelUUID
	}

	_, err := h.store.UpdateConfig(func(draft *config.PanelConfig) error {
		draft.Tunnel = req
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if err := h.mgr.RestartTunnel(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"tunnel_name": req.NamedTunnelName,
		"tunnel_uuid": req.NamedTunnelUUID,
	})
}

func (h *Handler) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"` // "all" | "xray" | "tunnel"
		Action string `json:"action"` // "start" | "stop" | "restart"
	}
	if err := decodeJSONBody(r, &req, 16*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数错误"})
		return
	}

	switch req.Target {
	case "xray":
		if req.Action == "stop" {
			h.mgr.StopXray()
		} else {
			if err := h.mgr.ReloadXray(); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
	case "tunnel":
		if req.Action == "stop" {
			_, _ = h.store.UpdateConfig(func(d *config.PanelConfig) error {
				d.Tunnel.Enabled = false
				d.Tunnel.PanelQuickTunnel = false
				return nil
			})
			h.mgr.StopTunnel()
		} else {
			_, _ = h.store.UpdateConfig(func(d *config.PanelConfig) error {
				d.Tunnel.Enabled = true
				return nil
			})
			if err := h.mgr.RestartTunnel(); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
	default: // "all"
		if req.Action == "stop" {
			_, _ = h.store.UpdateConfig(func(d *config.PanelConfig) error {
				d.Tunnel.Enabled = false
				d.Tunnel.PanelQuickTunnel = false
				return nil
			})
			h.mgr.StopTunnel()
			h.mgr.StopXray()
		} else {
			cur := h.store.GetConfig()
			if !cur.Tunnel.Enabled && !cur.Protocols.RealityEnabled && !cur.Protocols.IPv6SSEnabled {
				_, _ = h.store.UpdateConfig(func(d *config.PanelConfig) error {
					d.Tunnel.Enabled = true
					return nil
				})
			}
			if err := h.mgr.ReloadXray(); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			updated := h.store.GetConfig()
			if updated.Tunnel.Enabled || updated.Tunnel.PanelQuickTunnel {
				if err := h.mgr.RestartTunnel(); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
					return
				}
			}
		}
	}

	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleProtocolsApply(w http.ResponseWriter, r *http.Request) {
	var req config.ProtocolConfig
	if err := decodeJSONBody(r, &req, 64*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "协议配置格式无效"})
		return
	}

	oldCfg := h.store.GetConfig()
	if strings.TrimSpace(req.RealitySNI) != "" && !config.IsValidRealityDomain(req.RealitySNI) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Reality SNI 域名格式无效，请填写有效的域名 (例如 www.apple.com)"})
		return
	}
	if strings.TrimSpace(req.RealityPrivateKey) == "" {
		req.RealityPrivateKey = oldCfg.Protocols.RealityPrivateKey
	} else if _, _, err := config.DeriveRealityPublicKey(req.RealityPrivateKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Reality 私钥格式无效 (需为 32 字节 Base64 编码的 X25519 私钥)"})
		return
	}
	if req.RealityEnabled && req.RealityPort == oldCfg.ListenPort {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("Reality 监听端口 (%d) 不能与面板监听端口相同", req.RealityPort)})
		return
	}

	newCfg, err := h.store.UpdateConfig(func(draft *config.PanelConfig) error {
		draft.Protocols = req
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	// Reload Xray without touching active cloudflared tunnels unless dual-tunnel local ports changed
	if h.mgr.Status().XrayRunning || newCfg.Tunnel.Enabled || newCfg.Protocols.IPv6SSEnabled || newCfg.Protocols.RealityEnabled {
		if err := h.mgr.ReloadXray(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}

	portsChanged := oldCfg.Protocols.VLESSLocalPort != newCfg.Protocols.VLESSLocalPort ||
		oldCfg.Protocols.TrojanLocalPort != newCfg.Protocols.TrojanLocalPort ||
		oldCfg.Protocols.VLESSEnabled != newCfg.Protocols.VLESSEnabled ||
		oldCfg.Protocols.TrojanEnabled != newCfg.Protocols.TrojanEnabled
	if newCfg.Tunnel.Enabled && newCfg.Tunnel.Mode == "quick" && newCfg.Tunnel.QuickTopology == "dual" && portsChanged {
		_ = h.mgr.RestartTunnel()
	}

	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleRealityScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode    string   `json:"mode"`    // "preset" | "neighbor" | "custom"
		Domains []string `json:"domains"` // optional list of custom domains
		Custom  string   `json:"custom"`  // optional comma/newline separated custom domains
	}
	if err := decodeJSONBody(r, &req, 64*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "扫描请求参数无效"})
		return
	}

	customList := append([]string(nil), req.Domains...)
	if strings.TrimSpace(req.Custom) != "" {
		customList = append(customList, supervisor.ParseCustomDomainInputs(req.Custom)...)
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "custom" && len(customList) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请输入至少一个需要检测的域名 (如 www.apple.com)"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
	defer cancel()

	report := h.mgr.ScanRealitySNI(ctx, mode, customList)
	h.mgr.Logs().Add("panel", fmt.Sprintf("完成 Reality SNI 域名扫描 (模式: %s, 共检测 %d 个, 可用 %d 个)", report.Mode, report.Scanned, report.ValidCount))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"report": report,
	})
}

func (h *Handler) handlePreferredSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs         []config.PreferredIP `json:"ips"`
		BatchText   string               `json:"batch_text"`
		AppendBatch bool                 `json:"append_batch"`
		DefaultPort int                  `json:"default_port"`
	}
	if err := decodeJSONBody(r, &req, 512*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "优选列表格式错误"})
		return
	}

	var target []config.PreferredIP
	if strings.TrimSpace(req.BatchText) != "" {
		port := req.DefaultPort
		if port <= 0 {
			port = h.store.GetConfig().Protocols.TLSDefaultPort
		}
		parsedBatch := config.ParseBatchPreferredText(req.BatchText, port)
		if req.AppendBatch {
			existing := h.store.GetPreferred().IPs
			target = append(existing, parsedBatch...)
		} else {
			target = parsedBatch
		}
	} else {
		target = req.IPs
	}

	pref, err := h.store.SetPreferredIPs(target, "manual")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "preferred": pref})
}

func (h *Handler) handleFallbacksSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FallbackDomains      []config.FallbackDomain `json:"fallback_domains"`
		TLSDefaultPort       int                     `json:"tls_default_port"`
		ApplyPortToPreferred bool                    `json:"apply_port_to_preferred"`
	}
	if err := decodeJSONBody(r, &req, 128*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数格式错误"})
		return
	}

	cleanedFB := make([]config.FallbackDomain, 0, len(req.FallbackDomains))
	for _, fb := range req.FallbackDomains {
		host := strings.TrimSpace(fb.Host)
		if !config.IsValidHostOrIP(host) {
			continue
		}
		port := fb.Port
		if port < 1 || port > 65535 {
			port = 443
		}
		if req.ApplyPortToPreferred && req.TLSDefaultPort >= 1 && req.TLSDefaultPort <= 65535 {
			port = req.TLSDefaultPort
		}
		lbl := config.SanitizeLabel(fb.Label)
		if lbl == "" {
			lbl = "优选-" + host
		}
		cleanedFB = append(cleanedFB, config.FallbackDomain{
			Host:    host,
			Port:    port,
			Label:   lbl,
			Enabled: fb.Enabled,
		})
	}

	_, err := h.store.UpdateConfig(func(draft *config.PanelConfig) error {
		draft.FallbackDomains = cleanedFB
		if req.TLSDefaultPort >= 1 && req.TLSDefaultPort <= 65535 {
			draft.Protocols.TLSDefaultPort = req.TLSDefaultPort
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if req.ApplyPortToPreferred && req.TLSDefaultPort >= 1 && req.TLSDefaultPort <= 65535 {
		pref := h.store.GetPreferred()
		for i := range pref.IPs {
			pref.IPs[i].Port = req.TLSDefaultPort
		}
		_, _ = h.store.SetPreferredIPs(pref.IPs, pref.Source)
	}

	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) handleRotateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"` // "sub_uuid" | "client_token" | "node_uuid" | "reality_keys"
	}
	if err := decodeJSONBody(r, &req, 8*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数无效"})
		return
	}

	var newValue string
	extraResp := map[string]any{"ok": true}
	needXrayReload := false
	_, err := h.store.UpdateConfig(func(draft *config.PanelConfig) error {
		switch req.Target {
		case "sub_uuid":
			newValue = config.NewUUID()
			draft.SubUUID = newValue
		case "client_token":
			newValue = config.RandomHex(8)
			draft.ClientToken = newValue
		case "node_uuid":
			newValue = config.NewUUID()
			short := strings.Split(newValue, "-")[0]
			draft.Protocols.UUID = newValue
			draft.Protocols.VLESSPath = "vl-" + short
			draft.Protocols.TrojanPath = "tr-" + short
			needXrayReload = true
		case "reality_keys":
			priv, pub, genErr := config.GenerateRealityKeyPair()
			if genErr != nil {
				return genErr
			}
			sid := config.RandomHex(4)
			draft.Protocols.RealityPrivateKey = priv
			draft.Protocols.RealityPublicKey = pub
			draft.Protocols.RealityShortID = sid
			newValue = pub
			extraResp["private_key"] = priv
			extraResp["public_key"] = pub
			extraResp["short_id"] = sid
			needXrayReload = true
		default:
			return fmt.Errorf("未知的重置类型: %s", req.Target)
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if needXrayReload && h.mgr.Status().XrayRunning {
		_ = h.mgr.ReloadXray()
	}
	h.SyncStaticSubscriptions()
	extraResp["value"] = newValue
	writeJSON(w, http.StatusOK, extraResp)
}

func (h *Handler) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AdminUser          string `json:"admin_user"`
		CurrentPassword    string `json:"current_password"`
		NewPassword        string `json:"new_password"`
		AllowArgoPanel     bool   `json:"allow_argo_panel"`
		ServerHostOverride string `json:"server_host_override"`
		ListenPort         int    `json:"listen_port"`
	}
	if err := decodeJSONBody(r, &req, 32*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "设置参数无效"})
		return
	}

	oldCfg := h.store.GetConfig()
	var newPassHash string
	passwordChanged := false

	if strings.TrimSpace(req.NewPassword) != "" {
		if !config.VerifyPassword(req.CurrentPassword, oldCfg.AdminPassHash) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "当前密码验证失败"})
			return
		}
		if len(req.NewPassword) < 6 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "新密码长度不能少于 6 位"})
			return
		}
		h, err := config.HashPassword(req.NewPassword)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		newPassHash = h
		passwordChanged = true
	}

	portChanged := req.ListenPort > 0 && req.ListenPort <= 65535 && req.ListenPort != oldCfg.ListenPort
	if portChanged && h.switchPort != nil {
		if err := h.switchPort(req.ListenPort); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": fmt.Sprintf("切换端口 %d 失败: %v", req.ListenPort, err)})
			return
		}
	}

	newCfg, err := h.store.UpdateConfig(func(draft *config.PanelConfig) error {
		if u := strings.TrimSpace(req.AdminUser); u != "" {
			draft.AdminUser = u
		}
		if newPassHash != "" {
			draft.AdminPassHash = newPassHash
		}
		draft.AllowArgoPanel = req.AllowArgoPanel
		draft.Protocols.ServerHostOverride = strings.TrimSpace(req.ServerHostOverride)
		if portChanged {
			draft.ListenPort = req.ListenPort
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	if passwordChanged {
		h.sessions.ClearAll()
		sid := h.sessions.Create(newCfg.AdminUser)
		isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(sessionTTL.Seconds()),
		})
	}

	if portChanged {
		if synced := firewall.SyncPanelPorts(r.Context(), newCfg, false); len(synced) > 0 {
			h.mgr.Logs().Add("panel", "面板端口切换，系统防火墙已自动放行: "+strings.Join(synced, ", "))
		}
	}

	// If listen port changed and local tunnel (Quick or Named) points at ListenPort, restart tunnel smoothly
	if portChanged && (newCfg.Tunnel.PanelQuickTunnel || (newCfg.Tunnel.Enabled && ((newCfg.Tunnel.Mode == "quick" && newCfg.Tunnel.QuickTopology == "unified") || newCfg.Tunnel.Mode == "named"))) {
		go func() {
			time.Sleep(300 * time.Millisecond)
			_ = h.mgr.RestartTunnel()
		}()
	}

	h.SyncStaticSubscriptions()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"port_changed": portChanged,
		"listen_port":  newCfg.ListenPort,
	})
}

func (h *Handler) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	cfg := h.store.GetConfig()
	st := firewall.GetStatus(r.Context(), cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"firewall": st,
	})
}

func (h *Handler) handleFirewallAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // "enable" | "disable" | "reload" | "sync" | "install"
	}
	if err := decodeJSONBody(r, &req, 8*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "防火墙请求参数无效"})
		return
	}

	cfg := h.store.GetConfig()
	act := strings.ToLower(strings.TrimSpace(req.Action))
	var synced []string

	switch act {
	case "install":
		if err := firewall.InstallUFW(r.Context()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		h.mgr.Logs().Add("panel", "已完成系统 UFW 防火墙组件安装")
	case "enable":
		var err error
		synced, err = firewall.EnableUFW(r.Context(), cfg)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		h.mgr.Logs().Add("panel", "已安全启用 UFW 防火墙并自动放行保护端口: "+strings.Join(synced, ", "))
	case "disable":
		if err := firewall.DisableUFW(r.Context()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		h.mgr.Logs().Add("panel", "已停用 UFW 系统防火墙")
	case "reload":
		if err := firewall.ReloadUFW(r.Context()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		h.mgr.Logs().Add("panel", "已重载 UFW 防火墙规则")
	case "sync":
		synced = firewall.SyncPanelPorts(r.Context(), cfg, true)
		if len(synced) > 0 {
			h.mgr.Logs().Add("panel", "已一键同步放行面板及系统运行服务端口: "+strings.Join(synced, ", "))
		}
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "不支持的防火墙操作: " + req.Action})
		return
	}

	st := firewall.GetStatus(r.Context(), cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"synced":   synced,
		"firewall": st,
	})
}

func (h *Handler) handleFirewallRuleAdd(w http.ResponseWriter, r *http.Request) {
	var spec firewall.RuleSpec
	if err := decodeJSONBody(r, &spec, 16*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "规则参数格式无效"})
		return
	}
	if err := firewall.AddRule(r.Context(), spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	cfg := h.store.GetConfig()
	h.mgr.Logs().Add("panel", fmt.Sprintf("UFW 新增规则: %s %s/%s", spec.Action, spec.Port, spec.Proto))
	st := firewall.GetStatus(r.Context(), cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"firewall": st,
	})
}

func (h *Handler) handleFirewallRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Index int  `json:"index"`
		Force bool `json:"force"`
	}
	if err := decodeJSONBody(r, &req, 8*1024); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "删除规则参数无效"})
		return
	}
	cfg := h.store.GetConfig()
	if err := firewall.DeleteRule(r.Context(), req.Index, cfg, req.Force); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	h.mgr.Logs().Add("panel", fmt.Sprintf("UFW 已删除规则编号 [%d]", req.Index))
	st := firewall.GetStatus(r.Context(), cfg)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"firewall": st,
	})
}

func decodeJSONBody(r *http.Request, dst any, maxBytes int64) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	body, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
