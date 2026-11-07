package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

var fwMu sync.Mutex

// RuleItem represents a single rule entry parsed from UFW.
type RuleItem struct {
	Index     int    `json:"index"`
	To        string `json:"to"`
	Action    string `json:"action"`
	From      string `json:"from"`
	IPv6      bool   `json:"ipv6"`
	Comment   string `json:"comment,omitempty"`
	Protected bool   `json:"protected,omitempty"`
	Role      string `json:"role,omitempty"` // e.g. "SSH" | "面板端口" | "Reality" | "IPv6-SS"
}

// RuleSpec defines parameters for adding a UFW firewall rule.
type RuleSpec struct {
	Action  string `json:"action"`  // "allow" | "deny" | "reject" | "limit"
	Port    string `json:"port"`    // e.g. "443" or "10000:20000"
	Proto   string `json:"proto"`   // "tcp" | "udp" | "any"
	From    string `json:"from"`    // "" / "any" or IP / CIDR
	Comment string `json:"comment"` // optional label
}

// Status summarizes the current VPS internal firewall (UFW + other active backends) and active listening services.
type Status struct {
	IsRoot            bool           `json:"is_root"`
	UFWInstalled      bool           `json:"ufw_installed"`
	UFWActive         bool           `json:"ufw_active"`
	DefaultIncoming   string         `json:"default_incoming,omitempty"`
	DefaultOutgoing   string         `json:"default_outgoing,omitempty"`
	DetectedSSHPorts  []int          `json:"detected_ssh_ports"`
	PanelPort         int            `json:"panel_port"`
	RealityEnabled    bool           `json:"reality_enabled"`
	RealityPort       int            `json:"reality_port"`
	SSEnabled         bool           `json:"ss_enabled"`
	SSPort            int            `json:"ss_port"`
	OtherBackend      string         `json:"other_backend,omitempty"`
	Rules             []RuleItem     `json:"rules"`
	DetectedPorts     []DetectedPort `json:"detected_ports"`
	UnallowedServices []string       `json:"unallowed_services,omitempty"`
}

var (
	numberedRuleRe = regexp.MustCompile(`^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW IN|DENY IN|REJECT IN|LIMIT IN|ALLOW OUT|DENY OUT|REJECT OUT|LIMIT OUT|ALLOW|DENY|REJECT|LIMIT)\s{2,}(.+)$`)
	defaultPolRe   = regexp.MustCompile(`(?i)Default:\s*([a-z]+)\s*\(incoming\),\s*([a-z]+)\s*\(outgoing\)`)
	portRangeRe    = regexp.MustCompile(`^(\d{1,5})(?::(\d{1,5}))?$`)
)

// findSysBin locates system administration binaries even when systemd omits /usr/sbin or /sbin from PATH.
func findSysBin(name string) string {
	if p, err := exec.LookPath(name); err == nil && p != "" {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/local/bin"} {
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return cand
		}
	}
	return ""
}

func runCmd(ctx context.Context, bin string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, bin, args...)
	env := os.Environ()
	filtered := make([]string, 0, len(env)+3)
	for _, kv := range env {
		if strings.HasPrefix(kv, "LANG=") || strings.HasPrefix(kv, "LC_ALL=") || strings.HasPrefix(kv, "DEBIAN_FRONTEND=") {
			continue
		}
		filtered = append(filtered, kv)
	}
	filtered = append(filtered, "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	if !strings.Contains(os.Getenv("PATH"), "/usr/sbin") {
		filtered = append(filtered, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	cmd.Env = filtered

	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// DetectSSHPorts inspects /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/*.conf, defaulting to [22].
func DetectSSHPorts() []int {
	seen := make(map[int]bool)
	parseFile := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "Port") {
				if p, err := strconv.Atoi(fields[1]); err == nil && p >= 1 && p <= 65535 {
					seen[p] = true
				}
			}
		}
	}

	parseFile("/etc/ssh/sshd_config")
	if matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		for _, m := range matches {
			parseFile(m)
		}
	}

	if len(seen) == 0 {
		return []int{22}
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// ValidateAndNormalizeSpec validates user-supplied RuleSpec strictly without shell interpolation.
func ValidateAndNormalizeSpec(spec RuleSpec) (RuleSpec, error) {
	act := strings.ToLower(strings.TrimSpace(spec.Action))
	if act == "" {
		act = "allow"
	}
	switch act {
	case "allow", "deny", "reject", "limit":
	default:
		return RuleSpec{}, fmt.Errorf("不支持的规则动作: %s (可选 allow/deny/reject/limit)", spec.Action)
	}

	proto := strings.ToLower(strings.TrimSpace(spec.Proto))
	switch proto {
	case "", "any", "both", "tcp/udp", "all":
		proto = "any"
	case "tcp", "udp":
	default:
		return RuleSpec{}, fmt.Errorf("不支持的协议类型: %s (可选 tcp/udp/any)", spec.Proto)
	}

	portStr := strings.TrimSpace(spec.Port)
	portStr = strings.ReplaceAll(portStr, "-", ":")
	// Allow user to type "443/tcp" directly in port box
	if slash := strings.IndexByte(portStr, '/'); slash > 0 {
		subProto := strings.ToLower(strings.TrimSpace(portStr[slash+1:]))
		portStr = strings.TrimSpace(portStr[:slash])
		switch subProto {
		case "tcp", "udp":
			proto = subProto
		case "any", "both", "all":
			proto = "any"
		default:
			return RuleSpec{}, fmt.Errorf("不支持的协议后缀: %s (可选 tcp/udp/any)", subProto)
		}
	}

	m := portRangeRe.FindStringSubmatch(portStr)
	if len(m) == 0 {
		return RuleSpec{}, errors.New("端口格式无效，请输入 1-65535 单端口或 10000:20000 端口段")
	}
	pStart, err := strconv.Atoi(m[1])
	if err != nil || pStart < 1 || pStart > 65535 {
		return RuleSpec{}, errors.New("端口号超出有效范围 (1-65535)")
	}
	if m[2] != "" {
		pEnd, err := strconv.Atoi(m[2])
		if err != nil || pEnd < 1 || pEnd > 65535 || pEnd <= pStart {
			return RuleSpec{}, errors.New("端口段结束端口必须大于起始端口且不超过 65535")
		}
		if proto == "any" {
			return RuleSpec{}, errors.New("UFW 端口范围规则需明确指定 TCP 或 UDP 协议")
		}
		portStr = fmt.Sprintf("%d:%d", pStart, pEnd)
	} else {
		portStr = strconv.Itoa(pStart)
	}

	from := strings.TrimSpace(spec.From)
	if strings.EqualFold(from, "any") || strings.EqualFold(from, "anywhere") || from == "0.0.0.0/0" || from == "::/0" {
		from = ""
	}
	if from != "" {
		if net.ParseIP(from) == nil {
			if _, _, err := net.ParseCIDR(from); err != nil {
				return RuleSpec{}, fmt.Errorf("来源地址无效: %s (请留空表示任意来源，或填写有效 IP / CIDR 网段)", spec.From)
			}
		}
	}

	cmt := sanitizeComment(spec.Comment)
	return RuleSpec{
		Action:  act,
		Port:    portStr,
		Proto:   proto,
		From:    from,
		Comment: cmt,
	}, nil
}

func sanitizeComment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if r < 32 || r == 127 || r == '#' || r == '"' || r == '\'' || r == '`' {
			continue
		}
		b.WriteRune(r)
		count++
		if count >= 40 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// buildUFWRuleArgs converts a normalized RuleSpec into exact ufw CLI arguments (after "ufw").
func buildUFWRuleArgs(spec RuleSpec, includeComment bool) []string {
	var args []string
	if spec.From == "" {
		target := spec.Port
		if spec.Proto == "tcp" || spec.Proto == "udp" {
			target = spec.Port + "/" + spec.Proto
		}
		args = []string{spec.Action, target}
	} else {
		args = []string{spec.Action}
		if spec.Proto == "tcp" || spec.Proto == "udp" {
			args = append(args, "proto", spec.Proto)
		}
		args = append(args, "from", spec.From, "to", "any", "port", spec.Port)
	}
	if includeComment && spec.Comment != "" {
		args = append(args, "comment", spec.Comment)
	}
	return args
}

// ParseUFWNumberedOutput parses `LC_ALL=C ufw status numbered` (or `verbose`) output.
func ParseUFWNumberedOutput(out string) (active bool, defIn string, defOut string, rules []RuleItem) {
	lines := strings.Split(out, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(strings.ToLower(line), "status:") {
			active = strings.Contains(strings.ToLower(line), "active") && !strings.Contains(strings.ToLower(line), "inactive")
			continue
		}
		if dm := defaultPolRe.FindStringSubmatch(line); len(dm) == 3 {
			defIn = strings.ToLower(dm[1])
			defOut = strings.ToLower(dm[2])
			continue
		}
		m := numberedRuleRe.FindStringSubmatch(line)
		if len(m) != 5 {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		toField := strings.TrimSpace(m[2])
		actField := strings.TrimSpace(m[3])
		rest := strings.TrimSpace(m[4])

		comment := ""
		if hashIdx := strings.Index(rest, "#"); hashIdx >= 0 {
			comment = strings.TrimSpace(rest[hashIdx+1:])
			rest = strings.TrimSpace(rest[:hashIdx])
		}

		isV6 := strings.Contains(toField, "(v6)") || strings.Contains(rest, "(v6)")
		toClean := strings.TrimSpace(strings.ReplaceAll(toField, "(v6)", ""))
		fromClean := strings.TrimSpace(strings.ReplaceAll(rest, "(v6)", ""))
		if fromClean == "" {
			fromClean = "Anywhere"
		}

		rules = append(rules, RuleItem{
			Index:   idx,
			To:      toClean,
			Action:  actField,
			From:    fromClean,
			IPv6:    isV6,
			Comment: comment,
		})
	}
	return active, defIn, defOut, rules
}

// parseInactiveUFWUserRules reads saved tuple entries from /etc/ufw/user.rules when UFW is inactive.
func parseInactiveUFWUserRules() []RuleItem {
	var items []RuleItem
	readTuples := func(path string, ipv6 bool) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "### tuple ### ") {
				continue
			}
			// Format: ### tuple ### <action> <proto> <dst_port> <dst_ip> <src_port> <src_ip> <direction> [comment=...]
			body := strings.TrimPrefix(line, "### tuple ### ")
			comment := ""
			if cIdx := strings.Index(body, "comment="); cIdx >= 0 {
				rawHex := strings.Fields(body[cIdx+len("comment="):])[0]
				if decoded, err := decodeHexOrPlain(rawHex); err == nil {
					comment = decoded
				}
				body = strings.TrimSpace(body[:cIdx])
			}
			fields := strings.Fields(body)
			if len(fields) < 6 {
				continue
			}
			act := strings.ToUpper(fields[0]) + " IN"
			proto := fields[1]
			dstPort := fields[2]
			srcIP := fields[5]

			toDisp := dstPort
			if proto != "any" {
				toDisp = dstPort + "/" + proto
			}
			fromDisp := "Anywhere"
			if srcIP != "0.0.0.0/0" && srcIP != "::/0" && srcIP != "any" {
				fromDisp = srcIP
			}
			items = append(items, RuleItem{
				Index:   0,
				To:      toDisp,
				Action:  act,
				From:    fromDisp,
				IPv6:    ipv6,
				Comment: comment,
			})
		}
	}

	for _, p := range []string{"/etc/ufw/user.rules", "/lib/ufw/user.rules"} {
		if _, err := os.Stat(p); err == nil {
			readTuples(p, false)
			break
		}
	}
	for _, p := range []string{"/etc/ufw/user6.rules", "/lib/ufw/user6.rules"} {
		if _, err := os.Stat(p); err == nil {
			readTuples(p, true)
			break
		}
	}
	return items
}

func decodeHexOrPlain(s string) (string, error) {
	s = strings.Trim(s, `"'`)
	if len(s) >= 2 && len(s)%2 == 0 {
		isHex := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			buf := make([]byte, len(s)/2)
			for i := 0; i < len(s); i += 2 {
				v, _ := strconv.ParseUint(s[i:i+2], 16, 8)
				buf[i/2] = byte(v)
			}
			return string(buf), nil
		}
	}
	return s, nil
}

func annotateProtectedRules(rules []RuleItem, sshPorts []int, cfg config.PanelConfig, detectedSets ...[]DetectedPort) []RuleItem {
	sshMap := make(map[int]bool, len(sshPorts))
	for _, p := range sshPorts {
		sshMap[p] = true
	}
	var thirdParty []DetectedPort
	if len(detectedSets) > 0 {
		for _, dp := range detectedSets[0] {
			if dp.ManagedRole == "" {
				thirdParty = append(thirdParty, dp)
			}
		}
	}

	for i := range rules {
		port := extractLeadingPort(rules[i].To)
		if port <= 0 {
			if strings.EqualFold(rules[i].To, "OpenSSH") || strings.EqualFold(rules[i].To, "ssh") || rules[i].To == "22/tcp" {
				rules[i].Protected = true
				rules[i].Role = "SSH"
				continue
			}
		} else {
			switch {
			case sshMap[port]:
				rules[i].Protected = true
				rules[i].Role = "SSH"
				continue
			case port == cfg.ListenPort:
				rules[i].Protected = true
				rules[i].Role = "面板端口"
				continue
			case cfg.Protocols.RealityEnabled && port == cfg.Protocols.RealityPort:
				rules[i].Role = "Reality"
				continue
			case cfg.Protocols.IPv6SSEnabled && port == cfg.Protocols.SSPort:
				rules[i].Role = "IPv6-SS"
				continue
			}
		}

		// Protect ALLOW/LIMIT rules belonging to active external system services (e.g. Caddy, Nginx, Docker)
		actUpper := strings.ToUpper(strings.TrimSpace(rules[i].Action))
		if strings.HasPrefix(actUpper, "ALLOW") || strings.HasPrefix(actUpper, "LIMIT") {
			for _, dp := range thirdParty {
				covTCP, covUDP := ruleCoversPort(rules[i].To, dp.Port)
				if covTCP || covUDP {
					rules[i].Protected = true
					if dp.Process != "" {
						rules[i].Role = "服务: " + dp.Process
					} else {
						rules[i].Role = "系统监听服务"
					}
					break
				}
			}
		}
	}
	return rules
}

func extractLeadingPort(toField string) int {
	t := strings.TrimSpace(toField)
	if slash := strings.IndexByte(t, '/'); slash > 0 {
		t = t[:slash]
	}
	if colon := strings.IndexByte(t, ':'); colon > 0 {
		return 0
	}
	p, err := strconv.Atoi(strings.TrimSpace(t))
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

func detectOtherFirewallBackend(ctx context.Context, ufwActive bool) string {
	if fwCmd := findSysBin("firewall-cmd"); fwCmd != "" {
		if out, err := runCmd(ctx, fwCmd, "--state"); err == nil && strings.Contains(strings.ToLower(out), "running") {
			return "检测到 firewalld 正在运行（自动端口放行已同步兼容 firewalld；如需启用 UFW 建议先停用 firewalld 避免双防火墙冲突）"
		}
	}
	if !ufwActive {
		if ipt := findSysBin("iptables"); ipt != "" {
			if out, err := runCmd(ctx, ipt, "-S", "INPUT"); err == nil {
				if strings.Contains(out, "icmp-host-prohibited") || strings.Contains(out, "-j REJECT") {
					return "检测到系统 iptables INPUT 链含默认 REJECT 规则（常见于甲骨文云镜像，面板已自动插入 ACCEPT 放行规则）"
				}
			}
		}
	}
	return ""
}

func formatDetectedPortBadge(dp DetectedPort) string {
	protoDisp := dp.Proto
	if protoDisp == "any" {
		protoDisp = "tcp+udp"
	}
	if dp.Process != "" {
		return fmt.Sprintf("%d/%s (%s)", dp.Port, protoDisp, dp.Process)
	}
	return fmt.Sprintf("%d/%s", dp.Port, protoDisp)
}

// GetStatus queries current UFW installation, state, default policies, rule table, and active system listening services.
func GetStatus(ctx context.Context, cfg config.PanelConfig) Status {
	sshPorts := DetectSSHPorts()
	st := Status{
		IsRoot:           os.Geteuid() == 0,
		DetectedSSHPorts: sshPorts,
		PanelPort:        cfg.ListenPort,
		RealityEnabled:   cfg.Protocols.RealityEnabled,
		RealityPort:      cfg.Protocols.RealityPort,
		SSEnabled:        cfg.Protocols.IPv6SSEnabled,
		SSPort:           cfg.Protocols.SSPort,
		Rules:            []RuleItem{},
		DetectedPorts:    []DetectedPort{},
	}

	ufwBin := findSysBin("ufw")
	st.UFWInstalled = ufwBin != ""

	if !st.UFWInstalled || !st.IsRoot {
		st.OtherBackend = detectOtherFirewallBackend(ctx, false)
		st.DetectedPorts = DetectListeningPorts(ctx, cfg, sshPorts, nil, false, "")
		return st
	}

	numOut, _ := runCmd(ctx, ufwBin, "status", "numbered")
	verbOut, _ := runCmd(ctx, ufwBin, "status", "verbose")

	active, _, _, rules := ParseUFWNumberedOutput(numOut)
	_, defIn, defOut, _ := ParseUFWNumberedOutput(verbOut)
	st.UFWActive = active
	st.DefaultIncoming = defIn
	st.DefaultOutgoing = defOut
	st.OtherBackend = detectOtherFirewallBackend(ctx, active)

	if !active && len(rules) == 0 {
		rules = parseInactiveUFWUserRules()
	}

	detected := DetectListeningPorts(ctx, cfg, sshPorts, rules, active, defIn)
	st.DetectedPorts = detected
	for _, dp := range detected {
		if dp.BlockedByUFW && dp.UFWStatus == "unconfigured" {
			st.UnallowedServices = append(st.UnallowedServices, formatDetectedPortBadge(dp))
		}
	}
	st.Rules = annotateProtectedRules(rules, sshPorts, cfg, detected)
	return st
}

// InstallUFW installs the ufw package via the system package manager (apt/dnf/yum/apk).
func InstallUFW(ctx context.Context) error {
	fwMu.Lock()
	defer fwMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限才能安装系统防火墙组件")
	}
	if findSysBin("ufw") != "" {
		return nil
	}

	installCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	switch {
	case findSysBin("apt-get") != "":
		_, _ = runCmd(installCtx, findSysBin("apt-get"), "update", "-y")
		if out, err := runCmd(installCtx, findSysBin("apt-get"), "install", "-y", "ufw"); err != nil {
			return fmt.Errorf("apt-get 安装 ufw 失败: %v (%s)", err, lastLine(out))
		}
	case findSysBin("apk") != "":
		if out, err := runCmd(installCtx, findSysBin("apk"), "add", "--no-cache", "ufw"); err != nil {
			return fmt.Errorf("apk 安装 ufw 失败: %v (%s)", err, lastLine(out))
		}
	case findSysBin("dnf") != "":
		if out, err := runCmd(installCtx, findSysBin("dnf"), "install", "-y", "ufw"); err != nil {
			return fmt.Errorf("dnf 安装 ufw 失败: %v (%s)", err, lastLine(out))
		}
	case findSysBin("yum") != "":
		_, _ = runCmd(installCtx, findSysBin("yum"), "install", "-y", "epel-release")
		if out, err := runCmd(installCtx, findSysBin("yum"), "install", "-y", "ufw"); err != nil {
			return fmt.Errorf("yum 安装 ufw 失败: %v (%s)", err, lastLine(out))
		}
	default:
		return errors.New("未识别到支持的包管理器 (apt/apk/dnf/yum)，请手动执行包管理器安装 ufw")
	}

	if findSysBin("ufw") == "" {
		return errors.New("安装命令已完成，但未找到 ufw 可执行文件")
	}
	return nil
}

// AddRule adds a validated UFW rule.
func AddRule(ctx context.Context, rawSpec RuleSpec) error {
	spec, err := ValidateAndNormalizeSpec(rawSpec)
	if err != nil {
		return err
	}

	fwMu.Lock()
	defer fwMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限才能修改 UFW 防火墙规则")
	}
	ufwBin := findSysBin("ufw")
	if ufwBin == "" {
		return errors.New("系统尚未安装 UFW，请先点击“一键安装 UFW”")
	}

	args := buildUFWRuleArgs(spec, true)
	out, err := runCmd(ctx, ufwBin, args...)
	if err != nil && spec.Comment != "" {
		// Fallback for older UFW builds without `comment` support
		argsNoComment := buildUFWRuleArgs(spec, false)
		out, err = runCmd(ctx, ufwBin, argsNoComment...)
	}
	if err != nil {
		return fmt.Errorf("添加 UFW 规则失败: %s", firstNonEmpty(lastLine(out), err.Error()))
	}
	return nil
}

// DeleteRule deletes a UFW rule by its 1-based numbered index, guarding SSH, Panel, and active system service ports unless force=true.
func DeleteRule(ctx context.Context, ruleNum int, cfg config.PanelConfig, force bool) error {
	if ruleNum < 1 {
		return errors.New("无效的规则编号（仅启用状态下的编号规则支持按序号删除）")
	}

	fwMu.Lock()
	defer fwMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限才能删除 UFW 防火墙规则")
	}
	ufwBin := findSysBin("ufw")
	if ufwBin == "" {
		return errors.New("系统尚未安装 UFW")
	}

	numOut, _ := runCmd(ctx, ufwBin, "status", "numbered")
	active, _, _, rules := ParseUFWNumberedOutput(numOut)
	if !active {
		return errors.New("UFW 当前处于未启用状态，请启用后再按编号删除规则")
	}
	sshPorts := DetectSSHPorts()
	detected := DetectListeningPorts(ctx, cfg, sshPorts, rules, active, "deny")
	rules = annotateProtectedRules(rules, sshPorts, cfg, detected)
	var target *RuleItem
	for i := range rules {
		if rules[i].Index == ruleNum {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("未找到编号为 [%d] 的防火墙规则，请刷新列表后重试", ruleNum)
	}
	if target.Protected && !force {
		return fmt.Errorf("规则 [%d] (%s) 属于受保护的 %s 端口，直接删除可能导致服务器失联或运行中的服务外部访问中断！如确认已有其他规则放行，请确认强制删除", ruleNum, target.To, target.Role)
	}

	out, err := runCmd(ctx, ufwBin, "--force", "delete", strconv.Itoa(ruleNum))
	if err != nil {
		return fmt.Errorf("删除规则 [%d] 失败: %s", ruleNum, firstNonEmpty(lastLine(out), err.Error()))
	}
	return nil
}

// EnableUFW safely pre-allows SSH, Panel port, active proxy ports, and all unconfigured external listening services before enabling UFW.
func EnableUFW(ctx context.Context, cfg config.PanelConfig) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("需要 root 权限才能启用 UFW 防火墙")
	}
	ufwBin := findSysBin("ufw")
	if ufwBin == "" {
		return nil, errors.New("系统尚未安装 UFW，请先点击“一键安装 UFW”")
	}

	// 1. Pre-allow SSH + Panel + Reality/SS + all unconfigured running system services (e.g. Caddy 80/443) to prevent service interruption
	synced := SyncPanelPorts(ctx, cfg, true)

	fwMu.Lock()
	defer fwMu.Unlock()

	_, _ = runCmd(ctx, ufwBin, "default", "deny", "incoming")
	_, _ = runCmd(ctx, ufwBin, "default", "allow", "outgoing")

	out, err := runCmd(ctx, ufwBin, "--force", "enable")
	if err != nil {
		return synced, fmt.Errorf("启用 UFW 失败: %s", firstNonEmpty(lastLine(out), err.Error()))
	}
	return synced, nil
}

// DisableUFW disables UFW without deleting saved rules.
func DisableUFW(ctx context.Context) error {
	fwMu.Lock()
	defer fwMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限才能关闭 UFW 防火墙")
	}
	ufwBin := findSysBin("ufw")
	if ufwBin == "" {
		return errors.New("系统尚未安装 UFW")
	}
	out, err := runCmd(ctx, ufwBin, "disable")
	if err != nil {
		return fmt.Errorf("关闭 UFW 失败: %s", firstNonEmpty(lastLine(out), err.Error()))
	}
	return nil
}

// ReloadUFW reloads active UFW rules.
func ReloadUFW(ctx context.Context) error {
	fwMu.Lock()
	defer fwMu.Unlock()

	if os.Geteuid() != 0 {
		return errors.New("需要 root 权限才能重载 UFW")
	}
	ufwBin := findSysBin("ufw")
	if ufwBin == "" {
		return errors.New("系统尚未安装 UFW")
	}
	out, err := runCmd(ctx, ufwBin, "reload")
	if err != nil {
		return fmt.Errorf("重载 UFW 失败: %s", firstNonEmpty(lastLine(out), err.Error()))
	}
	return nil
}

// ManagedPortSpecs returns the list of UFW RuleSpecs that should be allowed for the given PanelConfig.
func ManagedPortSpecs(cfg config.PanelConfig, includeSSH bool) []RuleSpec {
	var specs []RuleSpec
	if includeSSH {
		for _, sp := range DetectSSHPorts() {
			specs = append(specs, RuleSpec{Action: "allow", Port: strconv.Itoa(sp), Proto: "tcp", Comment: "SSH"})
		}
	}
	if cfg.ListenPort >= 1 && cfg.ListenPort <= 65535 {
		specs = append(specs, RuleSpec{Action: "allow", Port: strconv.Itoa(cfg.ListenPort), Proto: "tcp", Comment: "Suoha-Panel"})
	}
	if cfg.Protocols.RealityEnabled && cfg.Protocols.RealityPort >= 1 && cfg.Protocols.RealityPort <= 65535 {
		specs = append(specs, RuleSpec{Action: "allow", Port: strconv.Itoa(cfg.Protocols.RealityPort), Proto: "tcp", Comment: "Suoha-Reality"})
	}
	if cfg.Protocols.IPv6SSEnabled && cfg.Protocols.SSPort >= 1 && cfg.Protocols.SSPort <= 65535 {
		specs = append(specs, RuleSpec{Action: "allow", Port: strconv.Itoa(cfg.Protocols.SSPort), Proto: "any", Comment: "Suoha-IPv6-SS"})
	}
	return specs
}

// AdditionalDetectedSpecs builds ALLOW RuleSpecs for active system listening services (e.g. Caddy 80/443, Nginx, Docker)
// that have UFWStatus == "unconfigured", strictly preserving any user-configured DENY/REJECT or source-IP restricted rules.
func AdditionalDetectedSpecs(detected []DetectedPort, existingRules []RuleItem, managed []RuleSpec) []RuleSpec {
	coveredManaged := make(map[string]bool, len(managed))
	for _, m := range managed {
		coveredManaged[m.Port] = true
	}

	var extra []RuleSpec
	for _, dp := range detected {
		portStr := strconv.Itoa(dp.Port)
		if coveredManaged[portStr] {
			continue
		}
		if dp.ManagedRole != "" && dp.ManagedRole != "SSH" {
			continue
		}
		if dp.UFWStatus != "unconfigured" {
			continue
		}
		missProto := MissingUFWProto(dp, existingRules)
		if missProto == "" {
			continue
		}
		cmt := CommentForDetectedPort(dp)
		if dp.ManagedRole == "SSH" {
			cmt = "SSH"
		}
		extra = append(extra, RuleSpec{
			Action:  "allow",
			Port:    portStr,
			Proto:   missProto,
			Comment: cmt,
		})
	}
	return extra
}

// SyncPanelPorts ensures SSH (when includeSSH=true), Panel ListenPort, enabled Reality / IPv6 SS ports,
// and unconfigured external listening system services (when includeSSH=true or firewall is active)
// are allowed in UFW (if installed), firewalld (if running), and restrictive iptables/ip6tables chains.
// Never auto-enables an inactive UFW firewall, and never overrides explicit DENY or source-IP restricted rules.
func SyncPanelPorts(ctx context.Context, cfg config.PanelConfig, includeSSH bool) []string {
	if os.Geteuid() != 0 {
		return nil
	}

	sshPorts := DetectSSHPorts()
	specs := ManagedPortSpecs(cfg, includeSSH)

	fwMu.Lock()
	defer fwMu.Unlock()

	var applied []string
	ufwBin := findSysBin("ufw")
	ufwActive := false
	defIn := ""
	var existingRules []RuleItem
	if ufwBin != "" {
		if numOut, err := runCmd(ctx, ufwBin, "status", "numbered"); err == nil {
			ufwActive, _, _, existingRules = ParseUFWNumberedOutput(numOut)
		}
		if verbOut, err := runCmd(ctx, ufwBin, "status", "verbose"); err == nil {
			_, defIn, _, _ = ParseUFWNumberedOutput(verbOut)
		}
		if !ufwActive && len(existingRules) == 0 {
			existingRules = parseInactiveUFWUserRules()
		}
	}

	fwCmd := findSysBin("firewall-cmd")
	fwCmdRunning := false
	if fwCmd != "" {
		if out, err := runCmd(ctx, fwCmd, "--state"); err == nil && strings.Contains(strings.ToLower(out), "running") {
			fwCmdRunning = true
		}
	}

	// Discover and protect other active external listening services (e.g. Caddy 80/443, Nginx, Docker)
	// whenever explicitly syncing/enabling UFW OR whenever an active firewall is already enforcing rules.
	if includeSSH || ufwActive || fwCmdRunning {
		detected := DetectListeningPorts(ctx, cfg, sshPorts, existingRules, ufwActive, defIn)
		extraSpecs := AdditionalDetectedSpecs(detected, existingRules, specs)
		specs = append(specs, extraSpecs...)
	}

	for _, spec := range specs {
		portNum, _ := strconv.Atoi(spec.Port)
		label := fmt.Sprintf("%s/%s", spec.Port, spec.Proto)
		if spec.Proto == "any" {
			label = fmt.Sprintf("%s/tcp+udp", spec.Port)
		}

		// 1. UFW (if installed, works both when active and inactive without auto-enabling UFW)
		if ufwBin != "" {
			args := buildUFWRuleArgs(spec, true)
			if _, err := runCmd(ctx, ufwBin, args...); err != nil {
				_, _ = runCmd(ctx, ufwBin, buildUFWRuleArgs(spec, false)...)
			}
		}

		// 2. firewalld (if active)
		if fwCmdRunning {
			if spec.Proto == "any" {
				_, _ = runCmd(ctx, fwCmd, "--permanent", fmt.Sprintf("--add-port=%d/tcp", portNum))
				_, _ = runCmd(ctx, fwCmd, "--permanent", fmt.Sprintf("--add-port=%d/udp", portNum))
			} else {
				_, _ = runCmd(ctx, fwCmd, "--permanent", fmt.Sprintf("--add-port=%d/%s", portNum, spec.Proto))
			}
		}

		// 3. Restrictive raw iptables / ip6tables (e.g., Oracle Cloud REJECT rules when neither UFW nor firewalld is active)
		if !ufwActive && !fwCmdRunning {
			ensureRestrictiveIPTablesAccept(ctx, "iptables", portNum, spec.Proto)
			ensureRestrictiveIPTablesAccept(ctx, "ip6tables", portNum, spec.Proto)
		}

		applied = append(applied, fmt.Sprintf("%s (%s)", label, spec.Comment))
	}

	if fwCmdRunning {
		_, _ = runCmd(ctx, fwCmd, "--reload")
	}
	return applied
}

// ensureRestrictiveIPTablesAccept inserts an ACCEPT rule at the top of INPUT only if INPUT has DROP policy or REJECT/DROP rules.
func ensureRestrictiveIPTablesAccept(ctx context.Context, binName string, port int, proto string) {
	bin := findSysBin(binName)
	if bin == "" {
		return
	}
	rulesOut, err := runCmd(ctx, bin, "-S", "INPUT")
	if err != nil {
		return
	}
	isRestrictive := strings.Contains(rulesOut, "-P INPUT DROP") ||
		strings.Contains(rulesOut, "-j REJECT") ||
		strings.Contains(rulesOut, "-j DROP")
	if !isRestrictive {
		return
	}

	protos := []string{proto}
	if proto == "any" {
		protos = []string{"tcp", "udp"}
	}
	portStr := strconv.Itoa(port)
	for _, p := range protos {
		// Skip if already present
		if _, err := runCmd(ctx, bin, "-C", "INPUT", "-p", p, "--dport", portStr, "-j", "ACCEPT"); err == nil {
			continue
		}
		_, _ = runCmd(ctx, bin, "-I", "INPUT", "1", "-p", p, "--dport", portStr, "-j", "ACCEPT")
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l != "" {
			return l
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}
