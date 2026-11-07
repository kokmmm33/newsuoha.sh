package firewall

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

// DetectedPort represents an external-facing TCP/UDP listening port currently active on the VPS.
type DetectedPort struct {
	Port         int      `json:"port"`
	Proto        string   `json:"proto"`                  // "tcp" | "udp" | "any"
	Process      string   `json:"process"`                // e.g. "caddy", "nginx", "sshd", "docker"
	PID          int      `json:"pid,omitempty"`          // owning process ID if visible
	ListenAddrs  []string `json:"listen_addrs"`           // e.g. ["0.0.0.0", "::"]
	ServiceHint  string   `json:"service_hint"`           // human-friendly description
	ManagedRole  string   `json:"managed_role,omitempty"` // "SSH" | "面板端口" | "Reality" | "IPv6-SS" | ""
	UFWStatus    string   `json:"ufw_status"`             // "allowed" | "restricted" | "denied" | "unconfigured"
	BlockedByUFW bool     `json:"blocked_by_ufw"`         // true when UFW active (deny incoming) and unconfigured/denied
}

type rawSocketEntry struct {
	proto   string // "tcp" | "udp"
	ip      net.IP
	port    int
	remPort int
	state   string // hex state e.g. "0A", "07"
	inode   uint64
}

type procOwner struct {
	pid  int
	name string
	exe  string
}

var dockerDNATRe = regexp.MustCompile(`-p\s+(tcp|udp)\b.*--dport\s+(\d{1,5})\s+-j\s+DNAT`)

// DetectListeningPorts scans Linux /proc/net/{tcp,tcp6,udp,udp6}, /proc/<pid>/fd, and Docker NAT rules
// to discover all external-facing listening services on the system, annotated with UFW coverage status.
func DetectListeningPorts(ctx context.Context, cfg config.PanelConfig, sshPorts []int, rules []RuleItem, ufwActive bool, defIncoming string) []DetectedPort {
	var rawEntries []rawSocketEntry
	for _, src := range []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		if data, err := os.ReadFile(src.path); err == nil {
			rawEntries = append(rawEntries, parseProcNetTable(string(data), src.proto)...)
		}
	}

	neededInodes := make(map[uint64]struct{}, len(rawEntries))
	for _, e := range rawEntries {
		if e.inode > 0 {
			neededInodes[e.inode] = struct{}{}
		}
	}
	inodeOwners := mapSocketInodesToProcesses(neededInodes)
	ephLow, ephHigh := readEphemeralPortRange()

	var dockerPorts []rawDockerPort
	if os.Geteuid() == 0 {
		dockerPorts = detectDockerDNATPorts(ctx)
	}

	detected := buildDetectedPorts(rawEntries, inodeOwners, dockerPorts, ephLow, ephHigh, cfg, sshPorts)
	return EvaluateUFWCoverage(detected, rules, ufwActive, defIncoming)
}

type rawDockerPort struct {
	port  int
	proto string // "tcp" | "udp"
}

// parseProcNetTable parses /proc/net/{tcp,tcp6,udp,udp6} text into candidate listening/unconnected external sockets.
func parseProcNetTable(content string, proto string) []rawSocketEntry {
	var out []rawSocketEntry
	lines := strings.Split(content, "\n")
	for idx, line := range lines {
		if idx == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		state := strings.ToUpper(fields[3])
		if proto == "tcp" && state != "0A" {
			// Only TCP_LISTEN (0x0A) sockets accept incoming TCP connections
			continue
		}
		if proto == "udp" && state != "07" {
			// Only unconnected UDP sockets (0x07 = TCP_CLOSE/UNCONN) act as general UDP listeners
			continue
		}

		ip, port, ok := parseProcHexAddrPort(fields[1])
		if !ok || port < 1 || port > 65535 {
			continue
		}
		_, remPort, okRem := parseProcHexAddrPort(fields[2])
		if proto == "udp" && (!okRem || remPort != 0) {
			continue
		}
		if !isExternalBindIP(ip) {
			continue
		}

		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		out = append(out, rawSocketEntry{
			proto:   proto,
			ip:      ip,
			port:    port,
			remPort: remPort,
			state:   state,
			inode:   inode,
		})
	}
	return out
}

// parseProcHexAddrPort decodes Linux /proc/net hex address:port (both 8-char IPv4 and 32-char IPv6) in native endianness.
func parseProcHexAddrPort(addrPort string) (net.IP, int, bool) {
	colon := strings.IndexByte(addrPort, ':')
	if colon <= 0 {
		return nil, 0, false
	}
	hexIP := addrPort[:colon]
	hexPort := addrPort[colon+1:]

	p, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return nil, 0, false
	}

	switch len(hexIP) {
	case 8:
		u, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return nil, 0, false
		}
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], uint32(u))
		return net.IPv4(b[0], b[1], b[2], b[3]), int(p), true
	case 32:
		var b [16]byte
		for i := 0; i < 4; i++ {
			u, err := strconv.ParseUint(hexIP[i*8:(i+1)*8], 16, 32)
			if err != nil {
				return nil, 0, false
			}
			binary.NativeEndian.PutUint32(b[i*4:(i+1)*4], uint32(u))
		}
		return net.IP(b[:]), int(p), true
	default:
		return nil, 0, false
	}
}

// isExternalBindIP returns true for 0.0.0.0, ::, or non-loopback/non-link-local interface addresses.
// Loopback sockets (127.0.0.0/8, ::1, ::ffff:127.0.0.1) such as Caddy admin :2019 or Xray local WS are excluded.
func isExternalBindIP(ip net.IP) bool {
	if len(ip) == 0 {
		return false
	}
	if ip.IsUnspecified() {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

func mapSocketInodesToProcesses(needed map[uint64]struct{}) map[uint64]procOwner {
	res := make(map[uint64]procOwner, len(needed))
	if len(needed) == 0 {
		return res
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return res
	}

	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(pe.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join("/proc", pe.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		var ownerCached *procOwner
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode := extractSocketInode(target)
			if inode == 0 {
				continue
			}
			if _, want := needed[inode]; !want {
				continue
			}
			if _, exists := res[inode]; exists {
				continue
			}
			if ownerCached == nil {
				o := readProcOwner(pid)
				ownerCached = &o
			}
			res[inode] = *ownerCached
			if len(res) >= len(needed) {
				return res
			}
		}
	}
	return res
}

func extractSocketInode(linkTarget string) uint64 {
	// Standard format: "socket:[12345]" or legacy "[0000]:12345"
	if strings.HasPrefix(linkTarget, "socket:[") && strings.HasSuffix(linkTarget, "]") {
		numStr := linkTarget[len("socket:[") : len(linkTarget)-1]
		v, _ := strconv.ParseUint(numStr, 10, 64)
		return v
	}
	if strings.HasPrefix(linkTarget, "[0000]:") {
		v, _ := strconv.ParseUint(linkTarget[len("[0000]:"):], 10, 64)
		return v
	}
	return 0
}

func readProcOwner(pid int) procOwner {
	pidStr := strconv.Itoa(pid)
	exePath, _ := os.Readlink(filepath.Join("/proc", pidStr, "exe"))
	exePath = strings.TrimSuffix(exePath, " (deleted)")

	commBytes, _ := os.ReadFile(filepath.Join("/proc", pidStr, "comm"))
	name := strings.TrimSpace(string(commBytes))
	if exeBase := filepath.Base(exePath); exeBase != "" && exeBase != "." && exeBase != "/" {
		// Prefer full binary basename when comm is truncated (15 chars) or generic thread name
		if name == "" || len(name) >= 15 || strings.HasPrefix(strings.ToLower(name), "main") {
			name = exeBase
		}
	}
	return procOwner{
		pid:  pid,
		name: name,
		exe:  exePath,
	}
}

func readEphemeralPortRange() (int, int) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 2 {
			low, err1 := strconv.Atoi(fields[0])
			high, err2 := strconv.Atoi(fields[1])
			if err1 == nil && err2 == nil && low > 0 && high > low {
				return low, high
			}
		}
	}
	return 32768, 60999
}

func detectDockerDNATPorts(ctx context.Context) []rawDockerPort {
	ipt := findSysBin("iptables")
	if ipt == "" {
		return nil
	}
	out, err := runCmd(ctx, ipt, "-t", "nat", "-S", "DOCKER")
	if err != nil || out == "" {
		return nil
	}
	var res []rawDockerPort
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		// Exclude localhost-only container mappings such as -d 127.0.0.1/32
		if strings.Contains(line, "-d 127.") {
			continue
		}
		m := dockerDNATRe.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		p, err := strconv.Atoi(m[2])
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		res = append(res, rawDockerPort{
			port:  p,
			proto: strings.ToLower(m[1]),
		})
	}
	return res
}

func isIgnoredSocketEntry(proto string, port int, owner procOwner, hasTCPOnSamePort bool, ephLow, ephHigh int, cfg config.PanelConfig) bool {
	procLow := strings.ToLower(owner.name)
	// cloudflared is strictly an outbound tunnel client; never expose its local metrics/QUIC sockets
	if procLow == "cloudflared" {
		return true
	}
	// LLMNR (5355) & mDNS (5353) are strictly link-local discovery protocols (e.g. systemd-resolved / avahi)
	if port == 5355 || port == 5353 {
		return true
	}
	if proto == "tcp" {
		return false
	}

	// Below checks apply to unconnected UDP sockets
	switch port {
	case 68, 546, 1900, 137, 138, 323:
		return true
	case 123:
		if procLow == "chronyd" || strings.HasPrefix(procLow, "systemd-") || procLow == "ntpd" {
			return true
		}
	case 51820:
		// Standard kernel-space WireGuard UDP port (has no userspace /proc/<pid>/fd owner)
		return false
	}
	switch procLow {
	case "dhclient", "dhcpcd", "udhcpc", "avahi-daemon", "systemd-network", "systemd-networkd", "systemd-resolve", "systemd-resolved", "systemd-timesync", "systemd-timesyncd":
		return true
	}

	// Configured Suoha SS port is always valid
	if cfg.Protocols.IPv6SSEnabled && port == cfg.Protocols.SSPort {
		return false
	}
	// If the same port also has a TCP listener (e.g. Caddy 443 TCP+UDP, Shadowsocks TCP+UDP), keep UDP
	if hasTCPOnSamePort {
		return false
	}
	// Known UDP server binaries are valid even on high ports
	for _, kw := range []string{
		"caddy", "nginx", "openresty", "traefik", "haproxy",
		"hysteria", "tuic", "sing-box", "v2ray", "xray",
		"openvpn", "wireguard", "wg", "tailscaled", "frps", "derper", "turnserver",
		"docker", "rootlesskit", "dnsmasq", "named", "coredns",
	} {
		if strings.Contains(procLow, kw) {
			// For Xray specifically, ignore random outbound UDP sockets inside ephemeral range unless SS port
			if kw == "xray" && port >= ephLow && port <= ephHigh {
				return true
			}
			return false
		}
	}

	// Unconnected UDP-only socket inside Linux ephemeral port range with unknown/client owner -> skip
	if port >= ephLow && port <= ephHigh {
		return true
	}
	return false
}

func buildDetectedPorts(
	entries []rawSocketEntry,
	owners map[uint64]procOwner,
	dockerPorts []rawDockerPort,
	ephLow, ephHigh int,
	cfg config.PanelConfig,
	sshPorts []int,
) []DetectedPort {
	tcpPorts := make(map[int]bool)
	for _, e := range entries {
		owner := owners[e.inode]
		if e.proto == "tcp" && !isIgnoredSocketEntry("tcp", e.port, owner, true, ephLow, ephHigh, cfg) {
			tcpPorts[e.port] = true
		}
	}

	type aggPort struct {
		port      int
		hasTCP    bool
		hasUDP    bool
		process   string
		pid       int
		addrSet   map[string]bool
		addrOrder []string
	}
	byPort := make(map[int]*aggPort)

	ensureAgg := func(port int) *aggPort {
		a, ok := byPort[port]
		if !ok {
			a = &aggPort{
				port:    port,
				addrSet: make(map[string]bool),
			}
			byPort[port] = a
		}
		return a
	}

	for _, e := range entries {
		owner := owners[e.inode]
		if isIgnoredSocketEntry(e.proto, e.port, owner, tcpPorts[e.port], ephLow, ephHigh, cfg) {
			continue
		}
		a := ensureAgg(e.port)
		if e.proto == "tcp" {
			a.hasTCP = true
		} else {
			a.hasUDP = true
		}
		if a.process == "" && owner.name != "" {
			a.process = owner.name
			a.pid = owner.pid
		} else if owner.name != "" && a.process == "docker-proxy" && owner.name != "docker-proxy" {
			a.process = owner.name
			a.pid = owner.pid
		}

		ipStr := formatBindIP(e.ip)
		if !a.addrSet[ipStr] {
			a.addrSet[ipStr] = true
			a.addrOrder = append(a.addrOrder, ipStr)
		}
	}

	for _, dp := range dockerPorts {
		a := ensureAgg(dp.port)
		if dp.proto == "udp" {
			a.hasUDP = true
		} else {
			a.hasTCP = true
		}
		if a.process == "" {
			a.process = "docker"
		}
		if !a.addrSet["0.0.0.0"] {
			a.addrSet["0.0.0.0"] = true
			a.addrOrder = append(a.addrOrder, "0.0.0.0")
		}
	}

	sshMap := make(map[int]bool, len(sshPorts))
	for _, p := range sshPorts {
		sshMap[p] = true
	}

	ports := make([]int, 0, len(portsCap(len(byPort))))
	for p := range byPort {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	result := make([]DetectedPort, 0, len(ports))
	for _, p := range ports {
		a := byPort[p]
		proto := "tcp"
		switch {
		case a.hasTCP && a.hasUDP:
			proto = "any"
		case a.hasUDP:
			proto = "udp"
		}

		managedRole := ""
		switch {
		case sshMap[p]:
			managedRole = "SSH"
		case p == cfg.ListenPort:
			managedRole = "面板端口"
		case cfg.Protocols.RealityEnabled && p == cfg.Protocols.RealityPort:
			managedRole = "Reality"
		case cfg.Protocols.IPv6SSEnabled && p == cfg.Protocols.SSPort:
			managedRole = "IPv6-SS"
		}

		proc := a.process
		if proc == "" && p == 51820 && a.hasUDP {
			proc = "wireguard"
		}
		sort.Strings(a.addrOrder)

		result = append(result, DetectedPort{
			Port:        p,
			Proto:       proto,
			Process:     proc,
			PID:         a.pid,
			ListenAddrs: a.addrOrder,
			ServiceHint: inferServiceHint(p, proto, proc, managedRole),
			ManagedRole: managedRole,
			UFWStatus:   "unconfigured",
		})
	}
	return result
}

func portsCap(n int) []int {
	return make([]int, n)
}

func formatBindIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	if ip.Equal(net.IPv6unspecified) {
		return "[::]"
	}
	return "[" + ip.String() + "]"
}

func inferServiceHint(port int, proto, proc, managedRole string) string {
	switch managedRole {
	case "SSH":
		return "SSH 远程终端"
	case "面板端口":
		return "Suoha 面板与订阅网关"
	case "Reality":
		return "Suoha VLESS+Reality 直连"
	case "IPv6-SS":
		return "Suoha IPv6 Shadowsocks"
	}

	pLow := strings.ToLower(proc)
	switch {
	case strings.Contains(pLow, "caddy"):
		if port == 443 && proto == "any" {
			return "Caddy HTTPS / HTTP3 (QUIC)"
		}
		return "Caddy Web / 反向代理"
	case strings.Contains(pLow, "nginx") || strings.Contains(pLow, "openresty"):
		return "Nginx Web / 反向代理"
	case strings.Contains(pLow, "apache") || pLow == "httpd":
		return "Apache HTTP 服务"
	case strings.Contains(pLow, "traefik"):
		return "Traefik 反向代理"
	case strings.Contains(pLow, "haproxy"):
		return "HAProxy 负载均衡"
	case strings.Contains(pLow, "docker"):
		return "Docker 容器端口映射"
	case strings.Contains(pLow, "x-ui"):
		return "X-UI / 3X-UI 面板"
	case strings.Contains(pLow, "sing-box"):
		return "sing-box 节点服务"
	case strings.Contains(pLow, "hysteria"):
		return "Hysteria 节点服务"
	case strings.Contains(pLow, "frps"):
		return "FRP 内网穿透服务端"
	case strings.Contains(pLow, "nezha"):
		return "哪吒探针面板"
	case strings.Contains(pLow, "tailscale"):
		return "Tailscale P2P 直连"
	case strings.Contains(pLow, "mysql") || strings.Contains(pLow, "mariadb"):
		return "MySQL / MariaDB 数据库"
	case strings.Contains(pLow, "postgres"):
		return "PostgreSQL 数据库"
	case strings.Contains(pLow, "redis"):
		return "Redis 缓存服务"
	case strings.Contains(pLow, "wireguard") || pLow == "wg":
		return "WireGuard VPN"
	}

	switch port {
	case 21:
		return "FTP 文件服务"
	case 22:
		return "SSH 远程终端"
	case 25, 465, 587:
		return "SMTP 邮件服务"
	case 53:
		return "DNS 域名解析"
	case 80:
		return "HTTP Web 服务"
	case 443:
		if proto == "any" {
			return "HTTPS / HTTP3 (QUIC)"
		}
		return "HTTPS Web 服务"
	case 3306:
		return "MySQL 数据库"
	case 5432:
		return "PostgreSQL 数据库"
	case 6379:
		return "Redis 服务"
	case 8080, 8443:
		return "Web / 反向代理服务"
	default:
		if proc != "" {
			return "系统运行服务 (" + proc + ")"
		}
		return "外部监听端口"
	}
}

func scanPortRuleCoverage(port int, rules []RuleItem) (allowTCPAny, allowUDPAny, restrictTCP, restrictUDP, denyTCP, denyUDP bool) {
	for _, r := range rules {
		act := strings.ToUpper(strings.TrimSpace(r.Action))
		if strings.Contains(act, "OUT") {
			continue
		}
		covTCP, covUDP := ruleCoversPort(r.To, port)
		if !covTCP && !covUDP {
			continue
		}

		fromNorm := strings.ToLower(strings.TrimSpace(r.From))
		isAnywhere := fromNorm == "" || fromNorm == "anywhere" || fromNorm == "0.0.0.0/0" || fromNorm == "::/0" || fromNorm == "any"

		switch {
		case strings.HasPrefix(act, "ALLOW") || strings.HasPrefix(act, "LIMIT"):
			if isAnywhere {
				if covTCP {
					allowTCPAny = true
				}
				if covUDP {
					allowUDPAny = true
				}
			} else {
				if covTCP {
					restrictTCP = true
				}
				if covUDP {
					restrictUDP = true
				}
			}
		case strings.HasPrefix(act, "DENY") || strings.HasPrefix(act, "REJECT"):
			if isAnywhere {
				if covTCP {
					denyTCP = true
				}
				if covUDP {
					denyUDP = true
				}
			}
		}
	}
	return
}

// EvaluateUFWCoverage computes UFWStatus ("allowed" | "restricted" | "denied" | "unconfigured")
// and BlockedByUFW for each detected listening port against parsed UFW rules.
func EvaluateUFWCoverage(detected []DetectedPort, rules []RuleItem, ufwActive bool, defIncoming string) []DetectedPort {
	denyByDefault := ufwActive && (defIncoming == "" || defIncoming == "deny" || defIncoming == "reject")

	for i := range detected {
		dp := &detected[i]
		needTCP := dp.Proto == "tcp" || dp.Proto == "any"
		needUDP := dp.Proto == "udp" || dp.Proto == "any"

		allowTCPAny, allowUDPAny, restrictTCP, restrictUDP, denyTCP, denyUDP := scanPortRuleCoverage(dp.Port, rules)

		fullAllow := (!needTCP || allowTCPAny) && (!needUDP || allowUDPAny)
		anyDeny := (needTCP && denyTCP) || (needUDP && denyUDP)
		// Preserve any explicit source-IP/CIDR allow rule (e.g. Cloudflare origin IP whitelist) without widening to Anywhere
		anyRestrict := restrictTCP || restrictUDP

		switch {
		case fullAllow:
			dp.UFWStatus = "allowed"
			dp.BlockedByUFW = false
		case anyDeny:
			dp.UFWStatus = "denied"
			dp.BlockedByUFW = ufwActive
		case anyRestrict:
			dp.UFWStatus = "restricted"
			dp.BlockedByUFW = false
		default:
			dp.UFWStatus = "unconfigured"
			dp.BlockedByUFW = denyByDefault
		}
	}
	return detected
}

// MissingUFWProto returns the UFW protocol ("tcp" | "udp" | "any" | "") that still needs an ALLOW rule
// for an "unconfigured" DetectedPort, avoiding duplicate rules if one protocol (e.g. 443/tcp) is already open.
func MissingUFWProto(dp DetectedPort, rules []RuleItem) string {
	if dp.UFWStatus != "unconfigured" {
		return ""
	}
	if dp.Proto != "any" {
		return dp.Proto
	}
	allowTCPAny, allowUDPAny, _, _, _, _ := scanPortRuleCoverage(dp.Port, rules)
	switch {
	case allowTCPAny && !allowUDPAny:
		return "udp"
	case !allowTCPAny && allowUDPAny:
		return "tcp"
	default:
		return "any"
	}
}

// CommentForDetectedPort builds a clean UFW comment tag for an auto-discovered system service port.
func CommentForDetectedPort(dp DetectedPort) string {
	if dp.Process != "" {
		return sanitizeComment("Sys-" + dp.Process)
	}
	return fmt.Sprintf("Sys-Port-%d", dp.Port)
}

func ruleCoversPort(toField string, port int) (coversTCP bool, coversUDP bool) {
	t := strings.TrimSpace(toField)
	if t == "" {
		return false, false
	}
	tLow := strings.ToLower(t)

	// Common UFW application profiles on Debian/Ubuntu
	switch tLow {
	case "openssh", "ssh":
		return port == 22, false
	case "nginx full", "apache full", "www full", "caddy":
		return port == 80 || port == 443, port == 443 && tLow == "caddy"
	case "nginx http", "apache", "www", "http":
		return port == 80, false
	case "nginx https", "apache secure", "www secure", "https":
		return port == 443, false
	case "dns", "bind9":
		return port == 53, port == 53
	}

	proto := "any"
	if slash := strings.IndexByte(tLow, '/'); slash > 0 {
		proto = strings.TrimSpace(tLow[slash+1:])
		tLow = strings.TrimSpace(tLow[:slash])
	}

	matchPort := false
	if colon := strings.IndexByte(tLow, ':'); colon > 0 {
		pStart, err1 := strconv.Atoi(tLow[:colon])
		pEnd, err2 := strconv.Atoi(tLow[colon+1:])
		if err1 == nil && err2 == nil && port >= pStart && port <= pEnd {
			matchPort = true
		}
	} else if p, err := strconv.Atoi(tLow); err == nil && p == port {
		matchPort = true
	}
	if !matchPort {
		return false, false
	}

	switch proto {
	case "tcp":
		return true, false
	case "udp":
		return false, true
	default:
		return true, true
	}
}
