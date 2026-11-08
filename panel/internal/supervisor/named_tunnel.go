package supervisor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

var (
	oauthLoginURLRe = regexp.MustCompile(`https://dash\.cloudflare\.com/[^\s"'<>]+`)
	oauthAnyCFURLRe = regexp.MustCompile(`https://[a-zA-Z0-9.-]*cloudflare\.com/[^\s"'<>]+`)
	uuidExtractRe   = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

// OAuthStatus represents the current Cloudflare browser OAuth (cert.pem) authorization state.
type OAuthStatus struct {
	Authorized  bool   `json:"authorized"`
	CertPath    string `json:"cert_path,omitempty"`
	CertUpdated string `json:"cert_updated,omitempty"`
	State       string `json:"state"` // "idle" | "starting" | "waiting" | "succeeded" | "error"
	AuthURL     string `json:"auth_url,omitempty"`
	Error       string `json:"error,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
}

// ProvisionNamedTunnelResult describes a created or reused Cloudflare Named Tunnel + DNS binding.
type ProvisionNamedTunnelResult struct {
	Domain     string `json:"domain"`
	TunnelName string `json:"tunnel_name"`
	TunnelUUID string `json:"tunnel_uuid"`
	CredFile   string `json:"cred_file"`
	Reused     bool   `json:"reused"`
}

// CloudflaredAuthDir returns the isolated directory storing cert.pem and <tunnel-uuid>.json files.
func CloudflaredAuthDir(dataDir string) string {
	return filepath.Join(dataDir, "cloudflared")
}

// OriginCertPath returns the panel-managed Cloudflare origin certificate path (/opt/suoha/cloudflared/cert.pem).
func OriginCertPath(dataDir string) string {
	return filepath.Join(CloudflaredAuthDir(dataDir), "cert.pem")
}

// TunnelCredFilePath returns the credentials JSON file path for a specific Named Tunnel UUID.
func TunnelCredFilePath(dataDir, tunnelUUID string) string {
	return filepath.Join(CloudflaredAuthDir(dataDir), strings.ToLower(strings.TrimSpace(tunnelUUID))+".json")
}

// NamedTunnelConfigPath returns the isolated local YAML config file path for running a Named Tunnel.
// Never write to ~/.cloudflared/config.yml because a default config.yml breaks Quick Tunnels.
func NamedTunnelConfigPath(dataDir string) string {
	return filepath.Join(dataDir, "runtime", "cloudflared_named.yaml")
}

// DefaultLegacyCloudflaredDirs returns legacy system directories checked once when importing an existing cert.pem.
func DefaultLegacyCloudflaredDirs() []string {
	return []string{"/root/.cloudflared", "/etc/cloudflared"}
}

func isValidOriginCertFile(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 32 {
		return false
	}
	return bytes.Contains(raw, []byte("-----BEGIN"))
}

type tunnelCredentialsDoc struct {
	AccountTag   string `json:"AccountTag"`
	TunnelID     string `json:"TunnelID"`
	TunnelSecret string `json:"TunnelSecret"`
	Endpoint     string `json:"Endpoint,omitempty"`
}

func parseTunnelCredFile(path string) (tunnelCredentialsDoc, bool) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) < 16 {
		return tunnelCredentialsDoc{}, false
	}
	var doc tunnelCredentialsDoc
	if err := json.Unmarshal(raw, &doc); err == nil && strings.TrimSpace(doc.TunnelID) != "" && strings.TrimSpace(doc.TunnelSecret) != "" {
		doc.TunnelID = strings.ToLower(strings.TrimSpace(doc.TunnelID))
		return doc, true
	}
	// Also handle compact token payload {"a":"...","t":"...","s":"..."} if written directly
	var short struct {
		A string `json:"a"`
		T string `json:"t"`
		S string `json:"s"`
		E string `json:"e,omitempty"`
	}
	if err := json.Unmarshal(raw, &short); err == nil && strings.TrimSpace(short.T) != "" && strings.TrimSpace(short.S) != "" {
		return tunnelCredentialsDoc{
			AccountTag:   strings.TrimSpace(short.A),
			TunnelID:     strings.ToLower(strings.TrimSpace(short.T)),
			TunnelSecret: strings.TrimSpace(short.S),
			Endpoint:     strings.TrimSpace(short.E),
		}, true
	}
	return tunnelCredentialsDoc{}, false
}

// EnsureOriginCert checks if /opt/suoha/cloudflared/cert.pem exists, or imports an existing legacy cert.pem if present.
func EnsureOriginCert(dataDir string, legacyDirs []string, logger *RingLog) (string, bool) {
	if strings.TrimSpace(dataDir) == "" {
		return "", false
	}
	target := OriginCertPath(dataDir)
	if isValidOriginCertFile(target) {
		return target, true
	}

	for _, dir := range legacyDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		cand := filepath.Join(dir, "cert.pem")
		if !isValidOriginCertFile(cand) {
			continue
		}
		raw, err := os.ReadFile(cand)
		if err != nil {
			continue
		}
		if err := os.MkdirAll(CloudflaredAuthDir(dataDir), 0700); err != nil {
			continue
		}
		if err := config.AtomicWriteFile(target, raw, 0600); err == nil {
			if logger != nil {
				logger.Add("panel", fmt.Sprintf("检测到已有 Cloudflare 授权凭据 (%s)，已自动导入复用", cand))
			}
			return target, true
		}
	}
	return target, false
}

func ensureLocalOrLegacyCredFile(dataDir string, legacyDirs []string, tunnelUUID string) (string, bool) {
	id := strings.ToLower(strings.TrimSpace(tunnelUUID))
	if !uuidExtractRe.MatchString(id) {
		return "", false
	}
	target := TunnelCredFilePath(dataDir, id)
	if doc, ok := parseTunnelCredFile(target); ok && doc.TunnelID == id {
		return target, true
	}
	for _, dir := range legacyDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		cand := filepath.Join(dir, id+".json")
		if doc, ok := parseTunnelCredFile(cand); ok && doc.TunnelID == id {
			if raw, err := os.ReadFile(cand); err == nil {
				_ = os.MkdirAll(CloudflaredAuthDir(dataDir), 0700)
				if config.AtomicWriteFile(target, raw, 0600) == nil {
					return target, true
				}
			}
		}
	}
	return target, false
}

func isMatchingTunnelNameForDomain(existingName, desiredName string) bool {
	en := strings.ToLower(strings.TrimSpace(existingName))
	dn := strings.ToLower(strings.TrimSpace(desiredName))
	if en == "" || dn == "" {
		return false
	}
	if en == dn {
		return true
	}
	if strings.HasPrefix(en, dn+"-") {
		suf := en[len(dn)+1:]
		if len(suf) == 4 {
			for i := 0; i < len(suf); i++ {
				c := suf[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// SetLegacyCloudflaredDirs overrides legacy ~/.cloudflared lookup directories (primarily for isolated tests).
func (m *Manager) SetLegacyCloudflaredDirs(dirs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := append([]string(nil), dirs...)
	m.customLegacyCFDirs = &cp
}

func (m *Manager) legacyCloudflaredDirs() []string {
	m.mu.RLock()
	custom := m.customLegacyCFDirs
	m.mu.RUnlock()
	if custom != nil {
		return *custom
	}
	if m.store != nil && m.store.SyncLegacyEnabled() {
		return DefaultLegacyCloudflaredDirs()
	}
	return nil
}

// OAuthStatus returns the live Cloudflare browser OAuth state and cert.pem presence.
func (m *Manager) OAuthStatus() OAuthStatus {
	var dataDir string
	if m.store != nil {
		dataDir = m.store.DataDir()
	}
	certPath, authorized := EnsureOriginCert(dataDir, m.legacyCloudflaredDirs(), m.logs)
	var certUpdated string
	if authorized {
		if st, err := os.Stat(certPath); err == nil {
			certUpdated = st.ModTime().Format("2006-01-02 15:04:05")
		}
	}

	m.mu.RLock()
	state := m.oauthState
	authURL := m.oauthURL
	errMsg := m.oauthErr
	startedAt := m.oauthStartedAt
	m.mu.RUnlock()

	if state == "" {
		state = "idle"
	}

	out := OAuthStatus{
		Authorized:  authorized,
		CertUpdated: certUpdated,
		State:       state,
		AuthURL:     authURL,
		Error:       errMsg,
		StartedAt:   startedAt,
	}
	if authorized {
		out.CertPath = certPath
	}
	return out
}

// CancelOAuthLogin terminates any in-progress `cloudflared tunnel login` session without affecting an existing cert.pem.
func (m *Manager) CancelOAuthLogin() {
	m.mu.Lock()
	cancel := m.oauthCancel
	m.oauthCancel = nil
	m.oauthState = "idle"
	m.oauthURL = ""
	m.oauthErr = ""
	m.oauthStartedAt = ""
	m.mu.Unlock()

	if cancel != nil {
		cancel()
		m.logs.Add("panel", "已取消正在等待的 Cloudflare 网页授权会话")
	}
}

// StartOAuthLogin spawns `cloudflared tunnel login` in an isolated staging HOME directory,
// captures the authorization URL from output, and saves cert.pem once browser authorization finishes.
func (m *Manager) StartOAuthLogin(edgeVer string) (OAuthStatus, error) {
	if m.store == nil || m.store.DataDir() == "" {
		return OAuthStatus{}, fmt.Errorf("未配置面板持久化数据目录")
	}
	dataDir := m.store.DataDir()
	cfBin, err := EnsureCloudflaredBinary(dataDir, m.logs)
	if err != nil {
		return OAuthStatus{}, err
	}
	if edgeVer != "6" {
		edgeVer = "4"
	}

	authDir := CloudflaredAuthDir(dataDir)
	if err := os.MkdirAll(authDir, 0700); err != nil {
		return OAuthStatus{}, fmt.Errorf("创建凭据目录失败: %w", err)
	}
	stagingHome := filepath.Join(authDir, fmt.Sprintf(".oauth_tmp_%d_%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(stagingHome, 0700); err != nil {
		return OAuthStatus{}, fmt.Errorf("创建临时授权目录失败: %w", err)
	}

	m.mu.Lock()
	if m.oauthCancel != nil {
		m.oauthCancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	sessionID := time.Now().UnixNano()
	m.oauthSessionID = sessionID
	m.oauthCancel = cancel
	m.oauthState = "starting"
	m.oauthURL = ""
	m.oauthErr = ""
	m.oauthStartedAt = time.Now().Format("2006-01-02 15:04:05")
	m.mu.Unlock()

	go m.runOAuthLoginSession(ctx, sessionID, cfBin, edgeVer, dataDir, stagingHome)

	// Wait briefly so the initial HTTP call immediately returns the generated Cloudflare OAuth URL
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		st := m.OAuthStatus()
		if st.State == "waiting" || st.State == "succeeded" || st.State == "error" || st.State == "idle" {
			return st, nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return m.OAuthStatus(), nil
}

func (m *Manager) runOAuthLoginSession(ctx context.Context, sessionID int64, cfBin, edgeVer, dataDir, stagingHome string) {
	defer func() {
		_ = os.RemoveAll(stagingHome)
	}()

	args := []string{
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"login",
	}
	cmd := exec.CommandContext(ctx, cfBin, args...)
	cmd.Env = buildIsolatedHomeEnv(stagingHome)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		m.mu.Lock()
		if m.oauthSessionID == sessionID {
			m.oauthState = "error"
			m.oauthErr = fmt.Sprintf("启动 cloudflared 网页授权失败: %v", err)
			m.oauthCancel = nil
		}
		m.mu.Unlock()
		m.logs.Add("cloudflared", fmt.Sprintf("[OAuth] 启动失败: %v", err))
		return
	}

	m.logs.Add("cloudflared", "[OAuth] 正在请求 Cloudflare 生成网页授权链接...")

	var lastNonEmptyLine string
	var lineMu sync.Mutex
	onLine := func(line string) {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			lineMu.Lock()
			lastNonEmptyLine = trimmed
			lineMu.Unlock()
		}
		u := extractCloudflareAuthURL(line)
		if u == "" {
			return
		}
		m.mu.Lock()
		if m.oauthSessionID == sessionID && m.oauthURL != u {
			m.oauthURL = u
			m.oauthState = "waiting"
			m.oauthErr = ""
		}
		m.mu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		streamLinesToLog(stdout, "cloudflared", m.logs, onLine)
	}()
	go func() {
		defer wg.Done()
		streamLinesToLog(stderr, "cloudflared", m.logs, onLine)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	stagedCert := filepath.Join(stagingHome, ".cloudflared", "cert.pem")
	if isValidOriginCertFile(stagedCert) {
		raw, err := os.ReadFile(stagedCert)
		if err == nil {
			targetCert := OriginCertPath(dataDir)
			if wErr := config.AtomicWriteFile(targetCert, raw, 0600); wErr == nil {
				m.mu.Lock()
				if m.oauthSessionID == sessionID {
					m.oauthState = "succeeded"
					m.oauthURL = ""
					m.oauthErr = ""
					m.oauthCancel = nil
				}
				m.mu.Unlock()
				m.logs.Add("panel", "Cloudflare 网页授权已完成，cert.pem 凭据已保存")
				return
			}
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oauthSessionID != sessionID {
		return
	}
	m.oauthCancel = nil
	if ctx.Err() == context.Canceled {
		if m.oauthState != "idle" {
			m.oauthState = "idle"
			m.oauthURL = ""
			m.oauthErr = ""
		}
		return
	}
	if ctx.Err() == context.DeadlineExceeded {
		m.oauthState = "error"
		m.oauthURL = ""
		m.oauthErr = "网页授权等待超时 (5 分钟)，请重新点击生成授权链接"
		return
	}
	lineMu.Lock()
	detail := lastNonEmptyLine
	lineMu.Unlock()
	if detail == "" && waitErr != nil {
		detail = waitErr.Error()
	}
	m.oauthState = "error"
	m.oauthErr = "网页授权未完成: " + detail
}

// RunInteractiveOAuthLogin executes Cloudflare browser authorization in an interactive CLI terminal.
func RunInteractiveOAuthLogin(ctx context.Context, dataDir, edgeVer string, legacyDirs []string, forceReauth bool, logger *RingLog, out io.Writer) (string, error) {
	if out == nil {
		out = os.Stdout
	}
	if !forceReauth {
		if certPath, ok := EnsureOriginCert(dataDir, legacyDirs, logger); ok {
			fmt.Fprintf(out, "检测到已存在有效的 Cloudflare 授权凭据: %s\n", certPath)
			return certPath, nil
		}
	}

	cfBin, err := EnsureCloudflaredBinary(dataDir, logger)
	if err != nil {
		return "", err
	}
	if edgeVer != "6" {
		edgeVer = "4"
	}

	authDir := CloudflaredAuthDir(dataDir)
	if err := os.MkdirAll(authDir, 0700); err != nil {
		return "", fmt.Errorf("创建凭据目录失败: %w", err)
	}
	stagingHome := filepath.Join(authDir, fmt.Sprintf(".cli_oauth_tmp_%d_%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.MkdirAll(stagingHome, 0700); err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(stagingHome)
	}()

	cmd := exec.CommandContext(ctx, cfBin, "--edge-ip-version", edgeVer, "--protocol", "http2", "tunnel", "login")
	cmd.Env = buildIsolatedHomeEnv(stagingHome)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("启动 cloudflared tunnel login 失败: %w", err)
	}

	fmt.Fprintln(out, "==========================================================")
	fmt.Fprintln(out, " 正在向 Cloudflare 请求网页授权链接，请稍候...")
	fmt.Fprintln(out, "==========================================================")

	printedURL := false
	var printMu sync.Mutex
	var lastLine string
	handleLine := func(line string) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return
		}
		printMu.Lock()
		lastLine = trimmed
		u := extractCloudflareAuthURL(trimmed)
		if u != "" && !printedURL {
			printedURL = true
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "请复制以下链接在浏览器中打开，登录 Cloudflare 并选择要绑定的主域名完成授权：")
			fmt.Fprintln(out, "----------------------------------------------------------")
			fmt.Fprintf(out, "  %s\n", u)
			fmt.Fprintln(out, "----------------------------------------------------------")
			fmt.Fprintln(out, "正在等待浏览器完成授权（完成后将自动继续，按 Ctrl+C 可取消）...")
		}
		printMu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		streamLinesToLog(stdout, "cloudflared", logger, handleLine)
	}()
	go func() {
		defer wg.Done()
		streamLinesToLog(stderr, "cloudflared", logger, handleLine)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	stagedCert := filepath.Join(stagingHome, ".cloudflared", "cert.pem")
	if isValidOriginCertFile(stagedCert) {
		raw, err := os.ReadFile(stagedCert)
		if err != nil {
			return "", fmt.Errorf("读取生成的 cert.pem 失败: %w", err)
		}
		target := OriginCertPath(dataDir)
		if err := config.AtomicWriteFile(target, raw, 0600); err != nil {
			return "", fmt.Errorf("保存 cert.pem 失败: %w", err)
		}
		fmt.Fprintf(out, "\n[成功] Cloudflare 网页授权已完成，凭据已保存至 %s\n", target)
		return target, nil
	}

	if ctx.Err() != nil {
		return "", fmt.Errorf("网页授权已取消或超时")
	}
	if waitErr != nil {
		return "", fmt.Errorf("网页授权失败 (%v): %s", waitErr, lastLine)
	}
	return "", fmt.Errorf("未检测到生成的 cert.pem 凭据文件: %s", lastLine)
}

func extractCloudflareAuthURL(line string) string {
	if m := oauthLoginURLRe.FindString(line); m != "" {
		return strings.TrimRight(m, ".,;)")
	}
	if m := oauthAnyCFURLRe.FindString(line); m != "" {
		low := strings.ToLower(m)
		if !strings.Contains(low, "developers.cloudflare.com") && !strings.Contains(low, "pkg.cloudflare.com") {
			return strings.TrimRight(m, ".,;)")
		}
	}
	return ""
}

func buildIsolatedHomeEnv(homeDir string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "TUNNEL_ORIGIN_CERT=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+homeDir)
	return env
}

// ProvisionNamedTunnel validates authorization, creates or recovers a Named Tunnel for rawDomain without
// deleting any existing cloud tunnels, and configures the Cloudflare DNS CNAME route (--overwrite-dns).
func (m *Manager) ProvisionNamedTunnel(ctx context.Context, rawDomain, edgeVer string) (ProvisionNamedTunnelResult, error) {
	if m.store == nil || m.store.DataDir() == "" {
		return ProvisionNamedTunnelResult{}, fmt.Errorf("未配置面板数据目录")
	}
	cfg := m.store.GetConfig()
	return ProvisionNamedTunnelWithStore(
		ctx,
		m.store.DataDir(),
		m.legacyCloudflaredDirs(),
		m.logs,
		rawDomain,
		edgeVer,
		cfg.Tunnel.NamedTunnelName,
		cfg.Tunnel.NamedTunnelUUID,
	)
}

// ProvisionNamedTunnelWithStore executes the Named Tunnel + DNS CNAME provisioning workflow against dataDir.
func ProvisionNamedTunnelWithStore(
	ctx context.Context,
	dataDir string,
	legacyDirs []string,
	logger *RingLog,
	rawDomain, edgeVer, existingName, existingUUID string,
) (ProvisionNamedTunnelResult, error) {
	domain := config.ExtractRealityDomain(rawDomain)
	if !config.IsValidRealityDomain(domain) || strings.HasSuffix(strings.ToLower(domain), ".trycloudflare.com") {
		return ProvisionNamedTunnelResult{}, fmt.Errorf("请填写有效的完整二级域名 (例如 sub.example.com)")
	}
	if edgeVer != "6" {
		edgeVer = "4"
	}

	certPath, ok := EnsureOriginCert(dataDir, legacyDirs, logger)
	if !ok {
		return ProvisionNamedTunnelResult{}, fmt.Errorf("尚未完成 Cloudflare 网页授权，请先点击获取授权链接并在浏览器中完成域名授权")
	}

	cfBin, err := EnsureCloudflaredBinary(dataDir, logger)
	if err != nil {
		return ProvisionNamedTunnelResult{}, err
	}
	if err := os.MkdirAll(CloudflaredAuthDir(dataDir), 0700); err != nil {
		return ProvisionNamedTunnelResult{}, fmt.Errorf("创建凭据目录失败: %w", err)
	}

	desiredName := config.BuildNamedTunnelName(domain)
	var tunName, tunUUID, credPath string
	reused := false

	// 1. Fast path: reuse already persisted UUID + local credential file for the same domain
	if existingUUID != "" && isMatchingTunnelNameForDomain(existingName, desiredName) {
		if p, valid := ensureLocalOrLegacyCredFile(dataDir, legacyDirs, existingUUID); valid {
			tunName = strings.TrimSpace(existingName)
			tunUUID = strings.ToLower(strings.TrimSpace(existingUUID))
			credPath = p
			reused = true
		}
	}

	// 2. Query Cloudflare account tunnels to reuse/recover existing tunnel or create a new one
	if tunUUID == "" {
		existingMap, listErr := listNamedTunnels(ctx, cfBin, certPath, edgeVer)
		if listErr != nil && logger != nil {
			logger.Add("cloudflared", fmt.Sprintf("[NamedTunnel] 查询已有隧道列表提示: %v", listErr))
		}

		if foundID, exists := existingMap[strings.ToLower(desiredName)]; exists && foundID != "" {
			if p, valid := ensureLocalOrLegacyCredFile(dataDir, legacyDirs, foundID); valid {
				tunName = desiredName
				tunUUID = foundID
				credPath = p
				reused = true
			} else if p, recErr := recoverTunnelCredentials(ctx, cfBin, certPath, edgeVer, foundID, dataDir); recErr == nil {
				tunName = desiredName
				tunUUID = foundID
				credPath = p
				reused = true
				if logger != nil {
					logger.Add("panel", fmt.Sprintf("已从 Cloudflare 恢复同名隧道凭据: %s (%s)", tunName, tunUUID))
				}
			} else {
				// Never delete existing cloud tunnels; allocate a fresh non-conflicting suffix instead
				altName := fmt.Sprintf("%s-%s", desiredName, config.RandomHex(2))
				id, p, cErr := createNamedTunnel(ctx, cfBin, certPath, edgeVer, altName, dataDir)
				if cErr != nil {
					return ProvisionNamedTunnelResult{}, cErr
				}
				tunName = altName
				tunUUID = id
				credPath = p
			}
		} else {
			id, p, cErr := createNamedTunnel(ctx, cfBin, certPath, edgeVer, desiredName, dataDir)
			if cErr != nil {
				// Handle race or text-list fallback if tunnel name already existed on Cloudflare
				if strings.Contains(strings.ToLower(cErr.Error()), "already exists") {
					altName := fmt.Sprintf("%s-%s", desiredName, config.RandomHex(2))
					id2, p2, cErr2 := createNamedTunnel(ctx, cfBin, certPath, edgeVer, altName, dataDir)
					if cErr2 != nil {
						return ProvisionNamedTunnelResult{}, cErr2
					}
					tunName = altName
					tunUUID = id2
					credPath = p2
				} else {
					return ProvisionNamedTunnelResult{}, cErr
				}
			} else {
				tunName = desiredName
				tunUUID = id
				credPath = p
			}
		}
	}

	if logger != nil {
		if reused {
			logger.Add("panel", fmt.Sprintf("复用命名隧道: %s (%s)", tunName, tunUUID))
		} else {
			logger.Add("panel", fmt.Sprintf("已创建命名隧道: %s (%s)", tunName, tunUUID))
		}
	}

	// 3. Configure or overwrite Cloudflare DNS CNAME record pointing domain -> <tunUUID>.cfargotunnel.com
	if err := routeNamedTunnelDNS(ctx, cfBin, certPath, edgeVer, tunUUID, domain); err != nil {
		return ProvisionNamedTunnelResult{}, err
	}
	if logger != nil {
		logger.Add("panel", fmt.Sprintf("已自动配置 Cloudflare DNS 路由解析: %s -> %s", domain, tunName))
	}

	return ProvisionNamedTunnelResult{
		Domain:     domain,
		TunnelName: tunName,
		TunnelUUID: tunUUID,
		CredFile:   credPath,
		Reused:     reused,
	}, nil
}

type cfTunnelListEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	DeletedAt string `json:"deleted_at"`
}

func listNamedTunnels(ctx context.Context, cfBin, certPath, edgeVer string) (map[string]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		cctx,
		cfBin,
		"--origincert", certPath,
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"list",
		"--output", "json",
	)
	cmd.Env = buildIsolatedHomeEnv(filepath.Dir(certPath))
	out, err := cmd.CombinedOutput()
	result := make(map[string]string)

	trimmed := bytes.TrimSpace(out)
	if idx := bytes.IndexByte(trimmed, '['); idx >= 0 {
		var entries []cfTunnelListEntry
		if jErr := json.Unmarshal(trimmed[idx:], &entries); jErr == nil {
			for _, e := range entries {
				del := strings.TrimSpace(e.DeletedAt)
				if del != "" && !strings.HasPrefix(del, "0001-01-01") {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(e.Name))
				id := strings.ToLower(strings.TrimSpace(e.ID))
				if name != "" && uuidExtractRe.MatchString(id) {
					result[name] = id
				}
			}
			return result, nil
		}
	}

	if err != nil {
		return result, fmt.Errorf("%s", summarizeCmdError(out, err))
	}
	return result, nil
}

func recoverTunnelCredentials(ctx context.Context, cfBin, certPath, edgeVer, tunnelUUID, dataDir string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	id := strings.ToLower(strings.TrimSpace(tunnelUUID))
	target := TunnelCredFilePath(dataDir, id)
	tmpCred := fmt.Sprintf("%s.recover.%d", target, time.Now().UnixNano())
	defer func() { _ = os.Remove(tmpCred) }()

	cmd := exec.CommandContext(
		cctx,
		cfBin,
		"--origincert", certPath,
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"token",
		"--cred-file", tmpCred,
		id,
	)
	cmd.Env = buildIsolatedHomeEnv(filepath.Dir(certPath))
	out, err := cmd.CombinedOutput()

	if doc, ok := parseTunnelCredFile(tmpCred); ok {
		normalized, _ := json.MarshalIndent(doc, "", "  ")
		if wErr := config.AtomicWriteFile(target, normalized, 0600); wErr == nil {
			return target, nil
		}
	}

	// Fallback: decode Base64 token printed to stdout ({"a":"...","t":"...","s":"..."})
	for _, tokenCand := range strings.Fields(string(out)) {
		if doc, ok := decodeBase64TunnelToken(tokenCand); ok && doc.TunnelID == id {
			normalized, _ := json.MarshalIndent(doc, "", "  ")
			if wErr := config.AtomicWriteFile(target, normalized, 0600); wErr == nil {
				return target, nil
			}
		}
	}

	if err != nil {
		return "", fmt.Errorf("恢复隧道凭据失败: %s", summarizeCmdError(out, err))
	}
	return "", fmt.Errorf("未能从 Cloudflare 获取隧道 %s 的凭据文件", id)
}

func decodeBase64TunnelToken(tok string) (tunnelCredentialsDoc, bool) {
	tok = strings.TrimSpace(tok)
	if len(tok) < 20 {
		return tunnelCredentialsDoc{}, false
	}
	var decoded []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(tok); err == nil && len(b) > 10 {
			decoded = b
			break
		}
	}
	if len(decoded) == 0 {
		return tunnelCredentialsDoc{}, false
	}
	var short struct {
		A string `json:"a"`
		T string `json:"t"`
		S string `json:"s"`
		E string `json:"e,omitempty"`
	}
	if err := json.Unmarshal(decoded, &short); err == nil && short.T != "" && short.S != "" {
		return tunnelCredentialsDoc{
			AccountTag:   strings.TrimSpace(short.A),
			TunnelID:     strings.ToLower(strings.TrimSpace(short.T)),
			TunnelSecret: strings.TrimSpace(short.S),
			Endpoint:     strings.TrimSpace(short.E),
		}, true
	}
	return tunnelCredentialsDoc{}, false
}

func createNamedTunnel(ctx context.Context, cfBin, certPath, edgeVer, tunnelName, dataDir string) (string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	authDir := CloudflaredAuthDir(dataDir)
	tmpCred := filepath.Join(authDir, fmt.Sprintf(".create_%d.json", time.Now().UnixNano()))
	defer func() { _ = os.Remove(tmpCred) }()

	cmd := exec.CommandContext(
		cctx,
		cfBin,
		"--origincert", certPath,
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"create",
		"--cred-file", tmpCred,
		tunnelName,
	)
	cmd.Env = buildIsolatedHomeEnv(authDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("创建命名隧道 %s 失败: %s", tunnelName, summarizeCmdError(out, err))
	}

	var tunUUID string
	if doc, ok := parseTunnelCredFile(tmpCred); ok {
		tunUUID = doc.TunnelID
	}
	if tunUUID == "" {
		if m := uuidExtractRe.FindString(string(out)); m != "" {
			tunUUID = strings.ToLower(m)
		}
	}
	if tunUUID == "" {
		return "", "", fmt.Errorf("隧道 %s 已执行创建但未能解析到 Tunnel UUID", tunnelName)
	}

	finalCred := TunnelCredFilePath(dataDir, tunUUID)
	if raw, rErr := os.ReadFile(tmpCred); rErr == nil && len(raw) > 0 {
		if wErr := config.AtomicWriteFile(finalCred, raw, 0600); wErr != nil {
			return "", "", fmt.Errorf("保存隧道凭据文件失败: %w", wErr)
		}
	} else if _, ok := parseTunnelCredFile(finalCred); !ok {
		return "", "", fmt.Errorf("未找到生成的隧道凭据文件 (%s)", finalCred)
	}

	return tunUUID, finalCred, nil
}

func routeNamedTunnelDNS(ctx context.Context, cfBin, certPath, edgeVer, tunnelUUID, domain string) error {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		cctx,
		cfBin,
		"--origincert", certPath,
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"route",
		"dns",
		"--overwrite-dns",
		tunnelUUID,
		domain,
	)
	cmd.Env = buildIsolatedHomeEnv(filepath.Dir(certPath))
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := summarizeCmdError(out, err)
		return fmt.Errorf("自动配置 DNS 解析 (%s) 失败 (请确认该域名属于当前网页授权所选的主域名，否则请点击「重新网页授权」): %s", domain, detail)
	}
	return nil
}

func summarizeCmdError(out []byte, err error) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l != "" {
			return l
		}
	}
	if err != nil {
		return err.Error()
	}
	return "未知错误"
}

// BuildNamedTunnelConfigYAML renders the local cloudflared YAML configuration routing domain -> unified HTTP gateway.
func BuildNamedTunnelConfigYAML(tunnelUUID, credPath, domain string, listenPort int) string {
	return fmt.Sprintf(
		"tunnel: %s\ncredentials-file: %s\n\ningress:\n  - hostname: %s\n    service: http://127.0.0.1:%d\n  - service: http_status:404\n",
		yamlSingleQuote(strings.TrimSpace(tunnelUUID)),
		yamlSingleQuote(strings.TrimSpace(credPath)),
		yamlSingleQuote(strings.TrimSpace(domain)),
		listenPort,
	)
}

func yamlSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (m *Manager) writeNamedTunnelConfig(tunnelUUID, credPath, domain string, listenPort int) (string, error) {
	yamlText := BuildNamedTunnelConfigYAML(tunnelUUID, credPath, domain, listenPort)
	cfgPath := NamedTunnelConfigPath(m.store.DataDir())
	if err := config.AtomicWriteFile(cfgPath, []byte(yamlText), 0600); err != nil {
		return "", err
	}
	return cfgPath, nil
}

func (m *Manager) superviseNamedTunnel(ctx context.Context, cfBin, edgeVer, cfgYAMLPath, tunUUID, domain string) {
	args := []string{
		"--edge-ip-version", edgeVer,
		"--protocol", "http2",
		"tunnel",
		"--no-autoupdate",
		"--config", cfgYAMLPath,
		"run",
		tunUUID,
	}

	for {
		if ctx.Err() != nil {
			return
		}
		m.logs.Add("cloudflared", fmt.Sprintf("[NamedTunnel] 正在连接固定命名隧道 (%s / %s) ...", domain, tunUUID))
		cmd := exec.CommandContext(ctx, cfBin, args...)
		cmd.Env = buildIsolatedHomeEnv(CloudflaredAuthDir(m.store.DataDir()))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			return nil
		}
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()

		if err := cmd.Start(); err != nil {
			m.mu.Lock()
			m.tunRunning = false
			m.tunState = "error"
			m.tunErr = err.Error()
			m.mu.Unlock()
			m.logs.Add("cloudflared", fmt.Sprintf("[NamedTunnel] 启动失败: %v", err))
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
		m.logs.Add("cloudflared", fmt.Sprintf("[NamedTunnel] 隧道连接断开 (%v)，4 秒后自动重连...", err))

		select {
		case <-ctx.Done():
			return
		case <-time.After(4 * time.Second):
		}
	}
}
