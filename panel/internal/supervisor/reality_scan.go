package supervisor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

// RealityCandidate represents a built-in candidate SNI domain for VLESS Reality camouflage.
type RealityCandidate struct {
	Domain   string `json:"domain"`
	Category string `json:"category"`
}

// RealityDomainResult contains server-side probe diagnostics for a single SNI domain.
type RealityDomainResult struct {
	Domain    string `json:"domain"`
	Category  string `json:"category,omitempty"`
	IP        string `json:"ip,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	TLS13     bool   `json:"tls13"`
	H2        bool   `json:"h2"`
	Valid     bool   `json:"valid"`
	Issuer    string `json:"issuer,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// RealityScanOptions configures server-side Reality SNI domain scanning.
type RealityScanOptions struct {
	Mode          string   // "preset" | "neighbor" | "custom"
	CustomDomains []string // Used when Mode == "custom"
	ServerIP      string   // Excluded from target resolution; used as /24 seed in "neighbor" mode
	Port          int      // Target TLS port (default 443)
	Timeout       time.Duration

	// Test hooks (unused in production)
	RootCAs          *x509.CertPool
	DialAddrOverride string
	AllowPrivateIP   bool
}

// RealityScanReport summarizes a completed scan operation.
type RealityScanReport struct {
	Mode       string                `json:"mode"`
	Scanned    int                   `json:"scanned"`
	ValidCount int                   `json:"valid_count"`
	Results    []RealityDomainResult `json:"results"`
	Note       string                `json:"note,omitempty"`
}

// DefaultRealityScanCandidates returns curated Apple (default) and global non-CF TLS 1.3 + H2 domains.
func DefaultRealityScanCandidates() []RealityCandidate {
	return []RealityCandidate{
		{Domain: "www.apple.com", Category: "Apple (默认)"},
		{Domain: "itunes.apple.com", Category: "Apple"},
		{Domain: "images.apple.com", Category: "Apple"},
		{Domain: "updates.cdn-apple.com", Category: "Apple CDN"},
		{Domain: "swdist.apple.com", Category: "Apple CDN"},
		{Domain: "mensura.cdn-apple.com", Category: "Apple CDN"},
		{Domain: "aod.itunes.apple.com", Category: "Apple CDN"},
		{Domain: "www.icloud.com", Category: "Apple"},
		{Domain: "www.microsoft.com", Category: "Microsoft"},
		{Domain: "learn.microsoft.com", Category: "Microsoft"},
		{Domain: "software.download.prss.microsoft.com", Category: "Microsoft CDN"},
		{Domain: "aws.amazon.com", Category: "AWS"},
		{Domain: "d1.awsstatic.com", Category: "AWS CloudFront"},
		{Domain: "dl.google.com", Category: "Google"},
		{Domain: "www.amd.com", Category: "Tech"},
		{Domain: "www.nvidia.com", Category: "Tech"},
		{Domain: "www.mozilla.org", Category: "Mozilla"},
		{Domain: "addons.mozilla.org", Category: "Mozilla"},
		{Domain: "www.lovelive-anime.jp", Category: "JP Media"},
		{Domain: "www.sony.com", Category: "Global"},
		{Domain: "www.samsung.com", Category: "Global"},
		{Domain: "www.yahoo.co.jp", Category: "JP Portal"},
	}
}

// ParseCustomDomainInputs splits comma, whitespace, or newline separated domain inputs.
func ParseCustomDomainInputs(raw string) []string {
	replacer := strings.NewReplacer(",", "\n", ";", "\n", " ", "\n", "\t", "\n", "\r", "\n")
	lines := strings.Split(replacer.Replace(raw), "\n")
	seen := make(map[string]bool)
	var out []string
	for _, item := range lines {
		d := config.ExtractRealityDomain(item)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
		if len(out) >= 40 {
			break
		}
	}
	return out
}

// ScanRealityDomains executes a preset, neighbor /24, or custom SNI availability scan from the server.
func ScanRealityDomains(ctx context.Context, opts RealityScanOptions) RealityScanReport {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode != "neighbor" && mode != "custom" {
		mode = "preset"
	}
	if opts.Port < 1 || opts.Port > 65535 {
		opts.Port = 443
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2500 * time.Millisecond
	}

	var candidates []RealityCandidate
	var note string

	switch mode {
	case "custom":
		seen := make(map[string]bool)
		for _, raw := range opts.CustomDomains {
			for _, d := range ParseCustomDomainInputs(raw) {
				if !seen[d] {
					seen[d] = true
					candidates = append(candidates, RealityCandidate{Domain: d, Category: "自定义检测"})
				}
			}
		}
	case "neighbor":
		srvIP := strings.TrimSpace(opts.ServerIP)
		if srvIP == "" {
			srvIP = DetectPublicIPv4()
			opts.ServerIP = srvIP
		}
		ip4 := net.ParseIP(srvIP)
		if ip4 != nil {
			ip4 = ip4.To4()
		}
		if ip4 == nil {
			note = "当前未检测到本机公网 IPv4 地址，已自动回退扫描内置优选域名池"
			candidates = DefaultRealityScanCandidates()
		} else {
			discovered := discoverNeighborTLSDomains(ctx, ip4, opts.Port)
			if len(discovered) == 0 {
				note = fmt.Sprintf("本机同网段 (%d.%d.%d.0/24) 未发现公开可复用的 TLS 1.3 证书域名，已自动补充内置优选域名检测", ip4[0], ip4[1], ip4[2])
				candidates = DefaultRealityScanCandidates()
			} else {
				note = fmt.Sprintf("已从本机同网段 (%d.%d.%d.0/24) 证书发现 %d 个候选域名并完成严格校验", ip4[0], ip4[1], ip4[2], len(discovered))
				for _, d := range discovered {
					candidates = append(candidates, RealityCandidate{Domain: d, Category: "同网段邻近"})
				}
			}
		}
	default:
		candidates = DefaultRealityScanCandidates()
	}

	results := probeCandidatesConcurrently(ctx, candidates, opts)

	// In preset or neighbor mode, sort valid domains first by ascending handshake latency.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Valid != results[j].Valid {
			return results[i].Valid
		}
		if results[i].Valid && results[i].LatencyMs != results[j].LatencyMs {
			return results[i].LatencyMs < results[j].LatencyMs
		}
		return false
	})

	validCount := 0
	for _, r := range results {
		if r.Valid {
			validCount++
		}
	}

	return RealityScanReport{
		Mode:       mode,
		Scanned:    len(results),
		ValidCount: validCount,
		Results:    results,
		Note:       note,
	}
}

func probeCandidatesConcurrently(ctx context.Context, candidates []RealityCandidate, opts RealityScanOptions) []RealityDomainResult {
	if len(candidates) == 0 {
		return []RealityDomainResult{}
	}
	results := make([]RealityDomainResult, len(candidates))
	workers := 10
	if len(candidates) < workers {
		workers = len(candidates)
	}
	jobs := make(chan int, len(candidates))
	for i := range candidates {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					results[idx] = RealityDomainResult{
						Domain:   candidates[idx].Domain,
						Category: candidates[idx].Category,
						Reason:   "扫描超时取消",
					}
					continue
				}
				results[idx] = ProbeRealityDomain(ctx, candidates[idx].Domain, candidates[idx].Category, opts)
			}
		}()
	}
	wg.Wait()
	return results
}

// ProbeRealityDomain verifies whether a domain is reachable from this server with valid X.509 cert, TLS 1.3, and ALPN h2.
func ProbeRealityDomain(ctx context.Context, rawDomain string, category string, opts RealityScanOptions) RealityDomainResult {
	domain := config.ExtractRealityDomain(rawDomain)
	res := RealityDomainResult{
		Domain:   domain,
		Category: category,
	}
	if !config.IsValidRealityDomain(domain) {
		res.Reason = "无效的域名格式 (需填写非 IP 的完整域名)"
		return res
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	port := opts.Port
	if port < 1 || port > 65535 {
		port = 443
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var dialTarget string
	if opts.DialAddrOverride != "" {
		dialTarget = opts.DialAddrOverride
		hostPart, _, err := net.SplitHostPort(dialTarget)
		if err == nil {
			res.IP = hostPart
		}
	} else {
		ips, err := net.DefaultResolver.LookupIPAddr(probeCtx, domain)
		if err != nil || len(ips) == 0 {
			res.Reason = "DNS 解析失败"
			return res
		}
		var chosen net.IP
		for _, item := range ips {
			ip := item.IP
			if ip == nil {
				continue
			}
			if !opts.AllowPrivateIP && !isSafePublicTargetIP(ip, opts.ServerIP) {
				continue
			}
			// Prefer IPv4 when available for widest Reality dest stability, fall back to IPv6
			if ip.To4() != nil {
				chosen = ip
				break
			}
			if chosen == nil {
				chosen = ip
			}
		}
		if chosen == nil {
			res.Reason = "域名解析结果包含内网保留地址或指向本机 IP"
			return res
		}
		res.IP = chosen.String()
		dialTarget = net.JoinHostPort(res.IP, strconv.Itoa(port))
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(probeCtx, "tcp", dialTarget)
	if err != nil {
		res.Reason = "TCP 443 连接超时或不可达"
		return res
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsCfg := &tls.Config{
		ServerName: domain,
		NextProtos: []string{"h2", "http/1.1"},
		RootCAs:    opts.RootCAs,
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		res.Reason = fmt.Sprintf("TLS 证书或握手校验失败 (%s)", compactErr(err))
		return res
	}
	defer tlsConn.Close()

	elapsed := time.Since(start).Milliseconds()
	if elapsed < 1 {
		elapsed = 1
	}
	res.LatencyMs = elapsed

	state := tlsConn.ConnectionState()
	res.TLS13 = state.Version == tls.VersionTLS13
	res.H2 = state.NegotiatedProtocol == "h2"
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if len(cert.Issuer.Organization) > 0 {
			res.Issuer = cert.Issuer.Organization[0]
		} else if cert.Issuer.CommonName != "" {
			res.Issuer = cert.Issuer.CommonName
		}
	}

	if !res.TLS13 {
		res.Reason = "目标站点不支持 TLS 1.3 (Reality 必须要求 TLS 1.3)"
		return res
	}
	if !res.H2 {
		res.Reason = "目标站点未开启 HTTP/2 (ALPN h2)"
		return res
	}

	res.Valid = true
	res.Reason = "TLS 1.3 + H2 验证通过"
	return res
}

// discoverNeighborTLSDomains scans sibling IPs in the same /24 IPv4 subnet on port 443 to extract public SAN domains.
func discoverNeighborTLSDomains(ctx context.Context, selfIP4 net.IP, port int) []string {
	type idxHost struct {
		lastOctet byte
	}
	jobs := make(chan idxHost, 254)
	for i := 1; i <= 254; i++ {
		if byte(i) == selfIP4[3] {
			continue
		}
		jobs <- idxHost{lastOctet: byte(i)}
	}
	close(jobs)

	var mu sync.Mutex
	seen := make(map[string]bool)
	var discovered []string

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	const workers = 32
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: 900 * time.Millisecond}
			for job := range jobs {
				if scanCtx.Err() != nil {
					return
				}
				mu.Lock()
				capped := len(discovered) >= 30
				mu.Unlock()
				if capped {
					return
				}

				ipStr := fmt.Sprintf("%d.%d.%d.%d", selfIP4[0], selfIP4[1], selfIP4[2], job.lastOctet)
				addr := net.JoinHostPort(ipStr, strconv.Itoa(port))
				conn, err := dialer.DialContext(scanCtx, "tcp", addr)
				if err != nil {
					continue
				}
				_ = conn.SetDeadline(time.Now().Add(900 * time.Millisecond))
				tconn := tls.Client(conn, &tls.Config{
					InsecureSkipVerify: true, // Verified strictly via ProbeRealityDomain in stage 2
					NextProtos:         []string{"h2", "http/1.1"},
				})
				err = tconn.HandshakeContext(scanCtx)
				if err == nil {
					st := tconn.ConnectionState()
					if st.Version == tls.VersionTLS13 && st.NegotiatedProtocol == "h2" && len(st.PeerCertificates) > 0 {
						leaf := st.PeerCertificates[0]
						names := append([]string(nil), leaf.DNSNames...)
						if leaf.Subject.CommonName != "" {
							names = append(names, leaf.Subject.CommonName)
						}
						mu.Lock()
						for _, raw := range names {
							d := strings.ToLower(strings.TrimSpace(raw))
							if strings.Contains(d, "*") || !config.IsValidRealityDomain(d) {
								continue
							}
							if !seen[d] && len(discovered) < 30 {
								seen[d] = true
								discovered = append(discovered, d)
							}
						}
						mu.Unlock()
					}
				}
				_ = tconn.Close()
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()
	return discovered
}

func isSafePublicTargetIP(ip net.IP, serverIP string) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if s := strings.TrimSpace(serverIP); s != "" {
		if self := net.ParseIP(s); self != nil && self.Equal(ip) {
			return false
		}
	}
	return true
}

func compactErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
