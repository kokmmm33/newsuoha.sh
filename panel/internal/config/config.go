package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	LegacySubPortFile  = "/etc/suoha_sub_port"
	LegacySubUUIDFile  = "/etc/suoha_sub_uuid"
	LegacySubTokenFile = "/etc/suoha_sub_token"
	LegacyWebDir       = "/var/www/suoha_sub"

	DefaultRealitySNI = "www.apple.com"
)

var (
	hostOrIPRegex = regexp.MustCompile(`^[a-zA-Z0-9.:-]+$`)
	domainOnlyRe  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	hexExcludeRe  = regexp.MustCompile(`[^0-9a-fA-F]+`)
	labelCleanRe  = regexp.MustCompile(`[\r\n\t#"'\\]+`)
	spaceRunRe    = regexp.MustCompile(`\s+`)
)

// TunnelConfig defines Cloudflare Argo tunnel runtime parameters.
type TunnelConfig struct {
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`               // "quick" | "token"
	EdgeIPVersion    string `json:"edge_ip_version"`    // "4" | "6"
	QuickTopology    string `json:"quick_topology"`     // "unified" | "dual"
	PanelQuickTunnel bool   `json:"panel_quick_tunnel"` // Auxiliary quick tunnel for panel/sub when in dual mode or when main tunnel off
	CFToken          string `json:"cf_token"`
	CustomDomain     string `json:"custom_domain"`
}

// ProtocolConfig defines supported protocols: VLESS-WS, Trojan-WS, VLESS-Reality-Vision direct, and IPv6 Shadowsocks direct.
type ProtocolConfig struct {
	NodeTag            string `json:"node_tag"`
	UUID               string `json:"uuid"`
	VLESSEnabled       bool   `json:"vless_enabled"`
	VLESSPath          string `json:"vless_path"`
	VLESSLocalPort     int    `json:"vless_local_port"`
	TrojanEnabled      bool   `json:"trojan_enabled"`
	TrojanPath         string `json:"trojan_path"`
	TrojanLocalPort    int    `json:"trojan_local_port"`
	RealityEnabled     bool   `json:"reality_enabled"`
	RealityPort        int    `json:"reality_port"`
	RealitySNI         string `json:"reality_sni"`
	RealityPrivateKey  string `json:"reality_private_key"`
	RealityPublicKey   string `json:"reality_public_key"`
	RealityShortID     string `json:"reality_short_id"`
	RealityFingerprint string `json:"reality_fingerprint"`
	IPv6SSEnabled      bool   `json:"ipv6_ss_enabled"`
	IPv6Addr           string `json:"ipv6_addr"`
	SSPort             int    `json:"ss_port"`
	SSPassword         string `json:"ss_password"`
	SSMethod           string `json:"ss_method"`
	TLSDefaultPort     int    `json:"tls_default_port"`
	ServerHostOverride string `json:"server_host_override"`
}

// FallbackDomain represents a built-in or user-edited fallback Cloudflare preferred domain.
type FallbackDomain struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// PreferredIP matches the schema used by suoha-client and sub_server.py.
type PreferredIP struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Latency string `json:"latency"`
	Speed   string `json:"speed"`
	Colo    string `json:"colo,omitempty"`
	Label   string `json:"label"`
}

// PreferredStore persists dynamic preferred IPs uploaded by suoha-client or edited in the panel.
type PreferredStore struct {
	UpdatedAt string        `json:"updated_at"`
	Source    string        `json:"source,omitempty"` // "client" | "manual"
	IPs       []PreferredIP `json:"ips"`
}

// PanelConfig is the root persistent state stored in <DataDir>/panel.json.
type PanelConfig struct {
	ListenPort      int              `json:"listen_port"`
	AdminUser       string           `json:"admin_user"`
	AdminPassHash   string           `json:"admin_pass_hash"`
	SubUUID         string           `json:"sub_uuid"`
	ClientToken     string           `json:"client_token"`
	AllowArgoPanel  bool             `json:"allow_argo_panel"`
	Tunnel          TunnelConfig     `json:"tunnel"`
	Protocols       ProtocolConfig   `json:"protocols"`
	FallbackDomains []FallbackDomain `json:"fallback_domains"`
}

// LegacyPaths allows overriding /etc and /var/www paths during tests.
type LegacyPaths struct {
	PortFile  string
	UUIDFile  string
	TokenFile string
	WebDir    string
}

// DefaultLegacyPaths returns standard production legacy file locations.
func DefaultLegacyPaths() LegacyPaths {
	return LegacyPaths{
		PortFile:  LegacySubPortFile,
		UUIDFile:  LegacySubUUIDFile,
		TokenFile: LegacySubTokenFile,
		WebDir:    LegacyWebDir,
	}
}

// Store provides thread-safe access and atomic persistence for PanelConfig and PreferredStore.
type Store struct {
	mu          sync.RWMutex
	dataDir     string
	legacy      LegacyPaths
	syncLegacy  bool
	cfg         PanelConfig
	pref        PreferredStore
	initPassPlain string // Non-empty only when newly created during this process invocation
}

// LoadOrInit loads existing configuration from dataDir or initializes a new one (migrating legacy suoha.sh files if present).
func LoadOrInit(dataDir string, legacy LegacyPaths, syncLegacy bool) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dataDir, err)
	}

	s := &Store{
		dataDir:    dataDir,
		legacy:     legacy,
		syncLegacy: syncLegacy,
	}

	cfgPath := filepath.Join(dataDir, "panel.json")
	prefPath := filepath.Join(dataDir, "preferred_ips.json")

	if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(raw, &s.cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", cfgPath, err)
		}
		needPersistUpgrade := strings.TrimSpace(s.cfg.Protocols.RealityPrivateKey) == ""
		s.normalizeLocked()
		if needPersistUpgrade {
			_ = s.saveConfigLocked()
		}
	} else {
		if err := s.initFreshWithMigrationLocked(); err != nil {
			return nil, err
		}
		if err := s.saveConfigLocked(); err != nil {
			return nil, err
		}
	}

	// Load preferred IPs (or migrate from /var/www/suoha_sub/preferred_ips.json)
	if raw, err := os.ReadFile(prefPath); err == nil {
		_ = json.Unmarshal(raw, &s.pref)
	} else if legacy.WebDir != "" {
		legacyPref := filepath.Join(legacy.WebDir, "preferred_ips.json")
		if lraw, err := os.ReadFile(legacyPref); err == nil {
			_ = json.Unmarshal(lraw, &s.pref)
			_ = s.savePrefLocked()
		}
	}
	if s.pref.IPs == nil {
		s.pref.IPs = []PreferredIP{}
	}

	if s.syncLegacy {
		s.syncLegacyFilesLocked()
	}
	return s, nil
}

func (s *Store) DataDir() string {
	return s.dataDir
}

func (s *Store) Legacy() LegacyPaths {
	return s.legacy
}

func (s *Store) SyncLegacyEnabled() bool {
	return s.syncLegacy
}

// InitialGeneratedPassword returns the plaintext initial password if a brand-new config was just initialized.
func (s *Store) InitialGeneratedPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initPassPlain
}

func (s *Store) GetConfig() PanelConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.cfg
	out.FallbackDomains = append([]FallbackDomain(nil), s.cfg.FallbackDomains...)
	return out
}

func (s *Store) UpdateConfig(mutator func(cfg *PanelConfig) error) (PanelConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	draft := s.cfg
	draft.FallbackDomains = append([]FallbackDomain(nil), s.cfg.FallbackDomains...)
	if err := mutator(&draft); err != nil {
		return s.cfg, err
	}
	s.cfg = draft
	s.normalizeLocked()
	if err := s.saveConfigLocked(); err != nil {
		return s.cfg, err
	}
	if s.syncLegacy {
		s.syncLegacyFilesLocked()
	}
	out := s.cfg
	out.FallbackDomains = append([]FallbackDomain(nil), s.cfg.FallbackDomains...)
	return out, nil
}

func (s *Store) GetPreferred() PreferredStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.pref
	out.IPs = append([]PreferredIP(nil), s.pref.IPs...)
	return out
}

func (s *Store) SetPreferredIPs(raw []PreferredIP, source string) (PreferredStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleaned := CleanPreferredIPs(raw)
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	s.pref = PreferredStore{
		UpdatedAt: nowStr,
		Source:    source,
		IPs:       cleaned,
	}
	if err := s.savePrefLocked(); err != nil {
		return s.pref, err
	}
	out := s.pref
	out.IPs = append([]PreferredIP(nil), s.pref.IPs...)
	return out, nil
}

func (s *Store) initFreshWithMigrationLocked() error {
	initPwd := RandomPassword(12)
	hash, err := HashPassword(initPwd)
	if err != nil {
		return err
	}
	s.initPassPlain = initPwd

	nodeUUID := NewUUID()
	shortID := strings.Split(nodeUUID, "-")[0]

	realityPriv, realityPub, err := GenerateRealityKeyPair()
	if err != nil {
		return err
	}

	cfg := PanelConfig{
		ListenPort:     RandomPortInRange(25000, 34999),
		AdminUser:      "admin",
		AdminPassHash:  hash,
		SubUUID:        NewUUID(),
		ClientToken:    RandomHex(8),
		AllowArgoPanel: true, // Default enabled so NAT/portless VPS users can also access via Argo HTTPS immediately; toggleable in UI/CLI
		Tunnel: TunnelConfig{
			Enabled:          false,
			Mode:             "quick",
			EdgeIPVersion:    "4",
			QuickTopology:    "unified",
			PanelQuickTunnel: false,
		},
		Protocols: ProtocolConfig{
			NodeTag:            "Argo_Node",
			UUID:               nodeUUID,
			VLESSEnabled:       true,
			VLESSPath:          "vl-" + shortID,
			VLESSLocalPort:     RandomPortInRange(18000, 19900),
			TrojanEnabled:      true,
			TrojanPath:         "tr-" + shortID,
			TrojanLocalPort:    0,
			RealityEnabled:     false,
			RealityPort:        RandomPortInRange(20000, 24999),
			RealitySNI:         DefaultRealitySNI,
			RealityPrivateKey:  realityPriv,
			RealityPublicKey:   realityPub,
			RealityShortID:     RandomHex(4),
			RealityFingerprint: "chrome",
			IPv6SSEnabled:      false,
			SSPort:             RandomPortInRange(30000, 39999),
			SSPassword:         RandomHex(8),
			SSMethod:           "aes-128-gcm",
			TLSDefaultPort:     443,
		},
		FallbackDomains: DefaultFallbackDomains(),
	}
	cfg.Protocols.TrojanLocalPort = cfg.Protocols.VLESSLocalPort + 1

	// Migrate legacy /etc/suoha_sub_* files if present
	if p := readTrimmedFile(s.legacy.PortFile); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 && v <= 65535 {
			cfg.ListenPort = v
		}
	}
	if u := readTrimmedFile(s.legacy.UUIDFile); isValidSafeToken(u) {
		cfg.SubUUID = u
	}
	if tok := readTrimmedFile(s.legacy.TokenFile); isValidSafeToken(tok) {
		cfg.ClientToken = tok
	}

	// Migrate /var/www/suoha_sub/meta.json if present
	if s.legacy.WebDir != "" {
		metaPath := filepath.Join(s.legacy.WebDir, "meta.json")
		if raw, err := os.ReadFile(metaPath); err == nil {
			var meta map[string]any
			if json.Unmarshal(raw, &meta) == nil {
				if v, ok := meta["uuid"].(string); ok && strings.TrimSpace(v) != "" {
					cfg.Protocols.UUID = strings.TrimSpace(v)
				}
				if v, ok := meta["urlpath_vless"].(string); ok && strings.TrimSpace(v) != "" {
					cfg.Protocols.VLESSPath = strings.TrimPrefix(strings.TrimSpace(v), "/")
				}
				if v, ok := meta["urlpath_trojan"].(string); ok && strings.TrimSpace(v) != "" {
					cfg.Protocols.TrojanPath = strings.TrimPrefix(strings.TrimSpace(v), "/")
				}
				if v, ok := meta["node_tag"].(string); ok && strings.TrimSpace(v) != "" {
					cfg.Protocols.NodeTag = strings.TrimSpace(v)
				}
				if v, ok := meta["mode"].(string); ok && v == "installed" {
					if dom, ok := meta["argo_vl"].(string); ok && strings.TrimSpace(dom) != "" && !strings.HasSuffix(dom, ".trycloudflare.com") {
						cfg.Tunnel.CustomDomain = strings.TrimSpace(dom)
						cfg.Tunnel.Mode = "token"
					}
				}
				if ssRaw, ok := meta["ss"].(map[string]any); ok {
					cfg.Protocols.IPv6SSEnabled = true
					if ip6, ok := ssRaw["ipv6_addr"].(string); ok {
						cfg.Protocols.IPv6Addr = strings.TrimSpace(ip6)
					}
					if pFloat, ok := ssRaw["ss_port"].(float64); ok && int(pFloat) > 0 {
						cfg.Protocols.SSPort = int(pFloat)
					}
					if pw, ok := ssRaw["ss_password"].(string); ok && pw != "" {
						cfg.Protocols.SSPassword = pw
					}
					if m, ok := ssRaw["ss_method"].(string); ok && m != "" {
						cfg.Protocols.SSMethod = m
					}
				}
			}
		}
	}

	s.cfg = cfg
	s.normalizeLocked()
	return nil
}

func (s *Store) normalizeLocked() {
	if s.cfg.ListenPort < 1 || s.cfg.ListenPort > 65535 {
		s.cfg.ListenPort = 25800
	}
	s.cfg.AdminUser = strings.TrimSpace(s.cfg.AdminUser)
	if s.cfg.AdminUser == "" {
		s.cfg.AdminUser = "admin"
	}
	if s.cfg.SubUUID == "" {
		s.cfg.SubUUID = NewUUID()
	}
	if s.cfg.ClientToken == "" {
		s.cfg.ClientToken = RandomHex(8)
	}
	if s.cfg.Tunnel.Mode != "token" {
		s.cfg.Tunnel.Mode = "quick"
	}
	if s.cfg.Tunnel.EdgeIPVersion != "6" {
		s.cfg.Tunnel.EdgeIPVersion = "4"
	}
	if s.cfg.Tunnel.QuickTopology != "dual" {
		s.cfg.Tunnel.QuickTopology = "unified"
	}
	s.cfg.Tunnel.CustomDomain = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s.cfg.Tunnel.CustomDomain, "https://"), "http://"))
	s.cfg.Tunnel.CustomDomain = strings.TrimRight(s.cfg.Tunnel.CustomDomain, "/")

	if strings.TrimSpace(s.cfg.Protocols.UUID) == "" {
		s.cfg.Protocols.UUID = NewUUID()
	}
	shortID := strings.Split(s.cfg.Protocols.UUID, "-")[0]
	s.cfg.Protocols.VLESSPath = sanitizeWSPath(s.cfg.Protocols.VLESSPath, "vl-"+shortID)
	s.cfg.Protocols.TrojanPath = sanitizeWSPath(s.cfg.Protocols.TrojanPath, "tr-"+shortID)
	if s.cfg.Protocols.TrojanPath == s.cfg.Protocols.VLESSPath {
		s.cfg.Protocols.TrojanPath = s.cfg.Protocols.TrojanPath + "-tr"
	}

	if s.cfg.Protocols.VLESSLocalPort < 1024 || s.cfg.Protocols.VLESSLocalPort > 65530 || s.cfg.Protocols.VLESSLocalPort == s.cfg.ListenPort {
		s.cfg.Protocols.VLESSLocalPort = 18201
		if s.cfg.ListenPort == 18201 {
			s.cfg.Protocols.VLESSLocalPort = 18301
		}
	}
	if s.cfg.Protocols.TrojanLocalPort < 1024 || s.cfg.Protocols.TrojanLocalPort > 65535 ||
		s.cfg.Protocols.TrojanLocalPort == s.cfg.Protocols.VLESSLocalPort ||
		s.cfg.Protocols.TrojanLocalPort == s.cfg.ListenPort {
		s.cfg.Protocols.TrojanLocalPort = s.cfg.Protocols.VLESSLocalPort + 1
		if s.cfg.Protocols.TrojanLocalPort == s.cfg.ListenPort {
			s.cfg.Protocols.TrojanLocalPort++
		}
	}
	if s.cfg.Protocols.SSPort < 1 || s.cfg.Protocols.SSPort > 65535 || s.cfg.Protocols.SSPort == s.cfg.ListenPort {
		s.cfg.Protocols.SSPort = 32888
	}
	if strings.TrimSpace(s.cfg.Protocols.SSPassword) == "" {
		s.cfg.Protocols.SSPassword = RandomHex(8)
	}
	if strings.TrimSpace(s.cfg.Protocols.SSMethod) == "" {
		s.cfg.Protocols.SSMethod = "aes-128-gcm"
	}

	// Normalize VLESS + Reality + Vision settings
	if s.cfg.Protocols.RealityPort < 1 || s.cfg.Protocols.RealityPort > 65535 ||
		s.cfg.Protocols.RealityPort == s.cfg.ListenPort ||
		s.cfg.Protocols.RealityPort == s.cfg.Protocols.VLESSLocalPort ||
		s.cfg.Protocols.RealityPort == s.cfg.Protocols.TrojanLocalPort ||
		s.cfg.Protocols.RealityPort == s.cfg.Protocols.SSPort {
		p := 24443
		for p == s.cfg.ListenPort || p == s.cfg.Protocols.VLESSLocalPort || p == s.cfg.Protocols.TrojanLocalPort || p == s.cfg.Protocols.SSPort {
			p++
		}
		s.cfg.Protocols.RealityPort = p
	}
	s.cfg.Protocols.RealitySNI = SanitizeRealitySNI(s.cfg.Protocols.RealitySNI)
	if normPriv, pub, err := DeriveRealityPublicKey(s.cfg.Protocols.RealityPrivateKey); err == nil {
		s.cfg.Protocols.RealityPrivateKey = normPriv
		s.cfg.Protocols.RealityPublicKey = pub
	} else if genPriv, genPub, err := GenerateRealityKeyPair(); err == nil {
		s.cfg.Protocols.RealityPrivateKey = genPriv
		s.cfg.Protocols.RealityPublicKey = genPub
	}
	s.cfg.Protocols.RealityShortID = SanitizeRealityShortID(s.cfg.Protocols.RealityShortID)
	s.cfg.Protocols.RealityFingerprint = SanitizeRealityFingerprint(s.cfg.Protocols.RealityFingerprint)

	if strings.TrimSpace(s.cfg.Protocols.NodeTag) == "" {
		s.cfg.Protocols.NodeTag = "Argo_Node"
	}
	if !IsValidCFPort(s.cfg.Protocols.TLSDefaultPort) {
		s.cfg.Protocols.TLSDefaultPort = 443
	}
	if s.cfg.FallbackDomains == nil {
		s.cfg.FallbackDomains = DefaultFallbackDomains()
	}
}

func (s *Store) saveConfigLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteFile(filepath.Join(s.dataDir, "panel.json"), data, 0600)
}

func (s *Store) savePrefLocked() error {
	data, err := json.MarshalIndent(s.pref, "", "  ")
	if err != nil {
		return err
	}
	if err := AtomicWriteFile(filepath.Join(s.dataDir, "preferred_ips.json"), data, 0644); err != nil {
		return err
	}
	if s.syncLegacy && s.legacy.WebDir != "" {
		_ = os.MkdirAll(s.legacy.WebDir, 0755)
		_ = AtomicWriteFile(filepath.Join(s.legacy.WebDir, "preferred_ips.json"), data, 0644)
	}
	return nil
}

func (s *Store) syncLegacyFilesLocked() {
	if s.legacy.PortFile != "" {
		_ = AtomicWriteFile(s.legacy.PortFile, []byte(fmt.Sprintf("%d\n", s.cfg.ListenPort)), 0644)
	}
	if s.legacy.UUIDFile != "" {
		_ = AtomicWriteFile(s.legacy.UUIDFile, []byte(s.cfg.SubUUID+"\n"), 0644)
	}
	if s.legacy.TokenFile != "" {
		_ = AtomicWriteFile(s.legacy.TokenFile, []byte(s.cfg.ClientToken+"\n"), 0600)
	}
}

// DefaultFallbackDomains returns the classic New-Suoha public preferred CDN domains.
func DefaultFallbackDomains() []FallbackDomain {
	return []FallbackDomain{
		{Host: "cf.090227.xyz", Port: 443, Label: "优选cf.090227", Enabled: true},
		{Host: "cloudflare.182682.xyz", Port: 443, Label: "优选182682", Enabled: true},
	}
}

// IsValidCFPort checks standard Cloudflare HTTPS edge ports (or any valid TCP port if customized).
func IsValidCFPort(port int) bool {
	return port >= 1 && port <= 65535
}

// AtomicWriteFile writes data to a temporary sibling file and atomically renames it into place.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SanitizeLabel strips control chars, quotes, hashes, and collapses spaces.
func SanitizeLabel(text string) string {
	t := labelCleanRe.ReplaceAllString(strings.TrimSpace(text), "")
	t = spaceRunRe.ReplaceAllString(t, "_")
	return t
}

// IsValidHostOrIP validates hostnames, IPv4, and unbracketed/bracketed IPv6 literals.
func IsValidHostOrIP(val string) bool {
	v := strings.TrimSpace(val)
	v = strings.TrimPrefix(strings.TrimSuffix(v, "]"), "[")
	if v == "" || len(v) > 253 {
		return false
	}
	return hostOrIPRegex.MatchString(v)
}

// BuildIPLabel mirrors sub_server.py's label builder for 100% compatibility with suoha-client.
func BuildIPLabel(idx int, item PreferredIP) string {
	raw := SanitizeLabel(item.Label)
	if raw != "" {
		return raw
	}
	parts := []string{fmt.Sprintf("优选%d", idx)}
	if c := SanitizeLabel(item.Colo); c != "" {
		parts = append(parts, c)
	}
	if l := SanitizeLabel(item.Latency); l != "" {
		parts = append(parts, l)
	}
	if sp := SanitizeLabel(item.Speed); sp != "" {
		parts = append(parts, strings.ReplaceAll(sp, "/s", ""))
	}
	return strings.Join(parts, "-")
}

// CleanPreferredIPs validates, normalizes, and caps preferred IP entries (max 100).
func CleanPreferredIPs(raw []PreferredIP) []PreferredIP {
	out := make([]PreferredIP, 0, len(raw))
	for _, item := range raw {
		if len(out) >= 100 {
			break
		}
		ipStr := strings.TrimSpace(item.IP)
		ipStr = strings.TrimPrefix(strings.TrimSuffix(ipStr, "]"), "[")
		if !IsValidHostOrIP(ipStr) {
			continue
		}
		port := item.Port
		if port < 1 || port > 65535 {
			port = 443
		}
		cleaned := PreferredIP{
			IP:      ipStr,
			Port:    port,
			Latency: SanitizeLabel(item.Latency),
			Speed:   SanitizeLabel(item.Speed),
			Colo:    SanitizeLabel(item.Colo),
			Label:   item.Label,
		}
		cleaned.Label = BuildIPLabel(len(out)+1, cleaned)
		out = append(out, cleaned)
	}
	return out
}

// ParseBatchPreferredText parses multiline user input like:
//   104.16.10.1
//   104.16.10.2:2053#香港优选
//   [2606:4700::1]:8443#IPv6优选
//   cf.example.com:443 备注名
func ParseBatchPreferredText(text string, defaultPort int) []PreferredIP {
	if defaultPort < 1 || defaultPort > 65535 {
		defaultPort = 443
	}
	lines := strings.Split(text, "\n")
	var items []PreferredIP
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var label string
		if idx := strings.Index(line, "#"); idx >= 0 {
			label = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		} else if fields := strings.Fields(line); len(fields) >= 2 {
			line = fields[0]
			label = strings.Join(fields[1:], "-")
		}
		if line == "" {
			continue
		}

		host := line
		port := defaultPort

		if strings.HasPrefix(line, "[") {
			// Bracketed IPv6: [2606:4700::1]:443 or [2606:4700::1]
			if end := strings.Index(line, "]"); end > 1 {
				host = line[1:end]
				rest := line[end+1:]
				if strings.HasPrefix(rest, ":") {
					if p, err := strconv.Atoi(rest[1:]); err == nil && p >= 1 && p <= 65535 {
						port = p
					}
				}
			}
		} else if strings.Count(line, ":") == 1 {
			// host:port or ipv4:port
			parts := strings.SplitN(line, ":", 2)
			host = parts[0]
			if p, err := strconv.Atoi(parts[1]); err == nil && p >= 1 && p <= 65535 {
				port = p
			}
		}

		if IsValidHostOrIP(host) {
			items = append(items, PreferredIP{
				IP:    host,
				Port:  port,
				Label: label,
			})
		}
	}
	return CleanPreferredIPs(items)
}

func sanitizeWSPath(raw, fallback string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "/")
	s = regexp.MustCompile(`[^a-zA-Z0-9._-]`).ReplaceAllString(s, "")
	// Prevent collision with reserved routes
	reserved := map[string]bool{
		"api": true, "health": true, "assets": true, "login": true,
	}
	if s == "" || reserved[strings.ToLower(s)] {
		return fallback
	}
	return s
}

func readTrimmedFile(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func isValidSafeToken(s string) bool {
	if len(s) < 6 || len(s) > 128 {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(s)
}

// ExtractRealityDomain strips scheme, path, and optional :port from user-entered SNI input.
func ExtractRealityDomain(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, ". ")
}

// IsValidRealityDomain checks whether a string is a valid non-IP FQDN suitable for TLS SNI.
func IsValidRealityDomain(raw string) bool {
	d := ExtractRealityDomain(raw)
	if d == "" || len(d) > 253 || net.ParseIP(d) != nil {
		return false
	}
	return domainOnlyRe.MatchString(d)
}

// SanitizeRealitySNI normalizes user SNI input and falls back to DefaultRealitySNI ("www.apple.com").
func SanitizeRealitySNI(raw string) string {
	d := ExtractRealityDomain(raw)
	if !IsValidRealityDomain(d) {
		return DefaultRealitySNI
	}
	return d
}

// SanitizeRealityShortID ensures shortId is a lowercase even-length hex string (2-16 chars).
func SanitizeRealityShortID(raw string) string {
	s := strings.ToLower(hexExcludeRe.ReplaceAllString(strings.TrimSpace(raw), ""))
	if len(s) > 16 {
		s = s[:16]
	}
	if len(s)%2 == 1 {
		s = "0" + s
	}
	if s == "" {
		return RandomHex(4)
	}
	return s
}

// SanitizeRealityFingerprint validates uTLS client fingerprint names.
func SanitizeRealityFingerprint(raw string) string {
	fp := strings.ToLower(strings.TrimSpace(raw))
	switch fp {
	case "chrome", "safari", "ios", "firefox", "edge", "android", "360", "qq", "random", "randomized":
		return fp
	default:
		return "chrome"
	}
}

