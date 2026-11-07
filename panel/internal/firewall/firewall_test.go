package firewall

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

func TestValidateAndNormalizeSpecAndBuildArgs(t *testing.T) {
	// 1. Single port with shorthand /tcp and comment sanitization
	spec, err := ValidateAndNormalizeSpec(RuleSpec{
		Action:  "ALLOW",
		Port:    "24443/tcp",
		Proto:   "any",
		From:    "anywhere",
		Comment: `Suoha-Reality "#inject"`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Action != "allow" || spec.Port != "24443" || spec.Proto != "tcp" || spec.From != "" {
		t.Fatalf("unexpected normalized spec: %+v", spec)
	}
	if spec.Comment != "Suoha-Reality inject" {
		t.Errorf("expected sanitized comment without quotes/#, got %q", spec.Comment)
	}
	gotArgs := buildUFWRuleArgs(spec, true)
	wantArgs := []string{"allow", "24443/tcp", "comment", "Suoha-Reality inject"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("buildUFWRuleArgs mismatch: got %v, want %v", gotArgs, wantArgs)
	}

	// 2. Port range with dash normalization and CIDR source IP
	rangeSpec, err := ValidateAndNormalizeSpec(RuleSpec{
		Action:  "limit",
		Port:    "10000-20000",
		Proto:   "udp",
		From:    "192.0.2.0/24",
		Comment: "PortRange",
	})
	if err != nil {
		t.Fatalf("unexpected error for valid port range: %v", err)
	}
	if rangeSpec.Port != "10000:20000" || rangeSpec.Proto != "udp" || rangeSpec.From != "192.0.2.0/24" {
		t.Fatalf("unexpected normalized rangeSpec: %+v", rangeSpec)
	}
	gotFromArgs := buildUFWRuleArgs(rangeSpec, false)
	wantFromArgs := []string{"limit", "proto", "udp", "from", "192.0.2.0/24", "to", "any", "port", "10000:20000"}
	if !reflect.DeepEqual(gotFromArgs, wantFromArgs) {
		t.Errorf("buildUFWRuleArgs with CIDR mismatch: got %v, want %v", gotFromArgs, wantFromArgs)
	}

	// 3. Reject invalid inputs & shell injection attempts
	invalidCases := []RuleSpec{
		{Action: "allow", Port: "0", Proto: "tcp"},
		{Action: "allow", Port: "70000", Proto: "tcp"},
		{Action: "allow", Port: "10000:20000", Proto: "any"}, // range requires tcp or udp
		{Action: "allow", Port: "20000:10000", Proto: "tcp"}, // end <= start
		{Action: "allow", Port: "443; rm -rf /", Proto: "tcp"},
		{Action: "allow", Port: "443/icmp", Proto: "any"},
		{Action: "drop", Port: "443", Proto: "tcp"},
		{Action: "allow", Port: "443", Proto: "tcp", From: "999.999.999.999"},
	}
	for i, tc := range invalidCases {
		if _, err := ValidateAndNormalizeSpec(tc); err == nil {
			t.Errorf("case #%d (%+v): expected validation error, got nil", i, tc)
		}
	}
}

func TestParseUFWNumberedOutputAndRoleProtection(t *testing.T) {
	verboseSample := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip`

	numberedSample := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 28080/tcp                  ALLOW IN    Anywhere                   # Suoha-Panel
[ 3] 24443/tcp                  ALLOW IN    Anywhere                   # Suoha-Reality
[ 4] 38388                      ALLOW IN    Anywhere                   # Suoha-IPv6-SS
[ 5] 3306/tcp                   DENY IN     198.51.100.12
[ 6] 24443/tcp (v6)             ALLOW IN    Anywhere (v6)              # Suoha-Reality`

	activeV, defIn, defOut, _ := ParseUFWNumberedOutput(verboseSample)
	if !activeV || defIn != "deny" || defOut != "allow" {
		t.Fatalf("unexpected verbose parse: active=%v defIn=%q defOut=%q", activeV, defIn, defOut)
	}

	activeN, _, _, rules := ParseUFWNumberedOutput(numberedSample)
	if !activeN || len(rules) != 6 {
		t.Fatalf("expected 6 parsed rules, got active=%v len=%d rules=%+v", activeN, len(rules), rules)
	}

	cfg := config.PanelConfig{
		ListenPort: 28080,
		Protocols: config.ProtocolConfig{
			RealityEnabled: true,
			RealityPort:    24443,
			IPv6SSEnabled:  true,
			SSPort:         38388,
		},
	}
	annotated := annotateProtectedRules(rules, []int{22}, cfg)

	// Rule 1: SSH -> Protected
	if !annotated[0].Protected || annotated[0].Role != "SSH" || annotated[0].Comment != "SSH" {
		t.Errorf("expected rule [1] to be protected SSH, got %+v", annotated[0])
	}
	// Rule 2: Panel -> Protected
	if !annotated[1].Protected || annotated[1].Role != "面板端口" {
		t.Errorf("expected rule [2] to be protected 面板端口, got %+v", annotated[1])
	}
	// Rule 3: Reality -> Role tagged, not lockout-protected
	if annotated[2].Protected || annotated[2].Role != "Reality" {
		t.Errorf("expected rule [3] to have Role=Reality and Protected=false, got %+v", annotated[2])
	}
	// Rule 4: IPv6-SS -> Role tagged
	if annotated[3].Role != "IPv6-SS" {
		t.Errorf("expected rule [4] Role=IPv6-SS, got %+v", annotated[3])
	}
	// Rule 5: Custom DENY from IP
	if annotated[4].Action != "DENY IN" || annotated[4].From != "198.51.100.12" || annotated[4].Protected {
		t.Errorf("unexpected rule [5]: %+v", annotated[4])
	}
	// Rule 6: IPv6 Reality rule
	if !annotated[5].IPv6 || annotated[5].To != "24443/tcp" || annotated[5].From != "Anywhere" || annotated[5].Role != "Reality" {
		t.Errorf("unexpected IPv6 rule [6]: %+v", annotated[5])
	}

	// Verify hex comment decoding used for /etc/ufw/user.rules
	hexStr := hex.EncodeToString([]byte("Suoha-Panel"))
	decoded, err := decodeHexOrPlain(hexStr)
	if err != nil || decoded != "Suoha-Panel" {
		t.Errorf("decodeHexOrPlain failed: got %q, err=%v", decoded, err)
	}
}

func TestManagedPortSpecsIncludesRealityWhenEnabled(t *testing.T) {
	cfg := config.PanelConfig{
		ListenPort: 32401,
		Protocols: config.ProtocolConfig{
			RealityEnabled: false,
			RealityPort:    24443,
		},
	}

	// Before enabling Reality: only Panel port (32401)
	specsOff := ManagedPortSpecs(cfg, false)
	if len(specsOff) != 1 || specsOff[0].Port != "32401" || specsOff[0].Proto != "tcp" {
		t.Fatalf("expected only panel port 32401/tcp when Reality disabled, got %+v", specsOff)
	}

	// After enabling Reality: both 32401/tcp and 24443/tcp must be included
	cfg.Protocols.RealityEnabled = true
	specsOn := ManagedPortSpecs(cfg, false)
	if len(specsOn) != 2 || specsOn[1].Port != "24443" || specsOn[1].Proto != "tcp" || specsOn[1].Comment != "Suoha-Reality" {
		t.Fatalf("expected panel port 32401/tcp + Reality port 24443/tcp when Reality enabled, got %+v", specsOn)
	}
}

func encodeProcIPv4Port(ip4 [4]byte, port int) string {
	u := binary.NativeEndian.Uint32(ip4[:])
	return fmt.Sprintf("%08X:%04X", u, port)
}

func TestCaddyAndOtherSystemServicesDetectionPreventsHTTP522(t *testing.T) {
	// Reproduce the exact scenario:
	// SSH(22), Suoha Panel(25329), Suoha Reality(2096), Suoha IPv6-SS(39019),
	// PLUS Caddy listening on :80 (tcp) + :443 (tcp+udp) + 127.0.0.1:2019 (admin loopback),
	// Xray local WS on 127.0.0.1:18201 (loopback), systemd-resolved on 127.0.0.53:53 & 0.0.0.0:5355 (LLMNR),
	// cloudflared outbound ephemeral UDP on 0.0.0.0:48123, and Docker container mapped on 8080/tcp.
	procTCP := fmt.Sprintf(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0
   2: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0
   3: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
   4: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0 100 0 0 10 0`,
		encodeProcIPv4Port([4]byte{0, 0, 0, 0}, 22),      // sshd
		encodeProcIPv4Port([4]byte{127, 0, 0, 1}, 2019),  // caddy admin loopback -> must exclude
		encodeProcIPv4Port([4]byte{127, 0, 0, 1}, 18201), // xray local WS -> must exclude
		encodeProcIPv4Port([4]byte{127, 0, 0, 53}, 53),   // systemd-resolved -> must exclude
		encodeProcIPv4Port([4]byte{0, 0, 0, 0}, 5355),    // LLMNR -> must exclude
	)

	procTCP6 := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0
   1: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0
   2: 00000000000000000000000000000000:62F1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2003 1 0
   3: 00000000000000000000000000000000:0830 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2004 1 0
   4: 00000000000000000000000000000000:986B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2005 1 0`

	procUDP6 := fmt.Sprintf(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3001 2 0
   1: 00000000000000000000000000000000:986B 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3002 2 0
   2: 00000000000000000000000000000000:%04X 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3003 2 0`,
		48123) // cloudflared ephemeral UDP -> must exclude

	var raw []rawSocketEntry
	raw = append(raw, parseProcNetTable(procTCP, "tcp")...)
	raw = append(raw, parseProcNetTable(procTCP6, "tcp")...)
	raw = append(raw, parseProcNetTable(procUDP6, "udp")...)

	owners := map[uint64]procOwner{
		1001: {pid: 510, name: "sshd"},
		1005: {pid: 412, name: "systemd-resolve"},
		2001: {pid: 888, name: "caddy"},
		2002: {pid: 888, name: "caddy"},
		2003: {pid: 920, name: "suoha-panel"},
		2004: {pid: 950, name: "xray"},
		2005: {pid: 950, name: "xray"},
		3001: {pid: 888, name: "caddy"},
		3002: {pid: 950, name: "xray"},
		3003: {pid: 960, name: "cloudflared"},
	}

	cfg := config.PanelConfig{
		ListenPort: 25329, // 0x62F1
		Protocols: config.ProtocolConfig{
			RealityEnabled: true,
			RealityPort:    2096, // 0x0830
			IPv6SSEnabled:  true,
			SSPort:         39019, // 0x986B
		},
	}

	dockerPorts := []rawDockerPort{{port: 8080, proto: "tcp"}}
	detected := buildDetectedPorts(raw, owners, dockerPorts, 32768, 60999, cfg, []int{22})

	// Expect exactly: 22(SSH), 80(caddy tcp), 443(caddy any), 2096(Reality), 8080(docker tcp), 25329(Panel), 39019(IPv6-SS)
	gotPorts := make([]int, 0, len(detected))
	byPort := make(map[int]DetectedPort)
	for _, dp := range detected {
		gotPorts = append(gotPorts, dp.Port)
		byPort[dp.Port] = dp
	}
	wantPorts := []int{22, 80, 443, 2096, 8080, 25329, 39019}
	if !reflect.DeepEqual(gotPorts, wantPorts) {
		t.Fatalf("detected ports mismatch: got %v, want %v (full=%+v)", gotPorts, wantPorts, detected)
	}

	// Verify Caddy 80/tcp and 443/any (TCP+UDP merged for HTTP/3 QUIC)
	if byPort[80].Proto != "tcp" || byPort[80].Process != "caddy" || byPort[80].ManagedRole != "" {
		t.Errorf("unexpected Caddy 80 detection: %+v", byPort[80])
	}
	if byPort[443].Proto != "any" || byPort[443].Process != "caddy" || byPort[443].ManagedRole != "" {
		t.Errorf("unexpected Caddy 443 detection: %+v", byPort[443])
	}

	// Simulate active UFW that previously ONLY allowed the 4 Suoha/SSH ports (the HTTP 522 bug scenario)
	ufwBefore := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
[ 2] 25329/tcp                  ALLOW IN    Anywhere                   # Suoha-Panel
[ 3] 39019                      ALLOW IN    Anywhere                   # Suoha-IPv6-SS
[ 4] 2096/tcp                   ALLOW IN    Anywhere                   # Suoha-Reality`

	active, _, _, existingRules := ParseUFWNumberedOutput(ufwBefore)
	evaluated := EvaluateUFWCoverage(detected, existingRules, active, "deny")

	evalMap := make(map[int]DetectedPort)
	for _, dp := range evaluated {
		evalMap[dp.Port] = dp
	}
	if !evalMap[80].BlockedByUFW || evalMap[80].UFWStatus != "unconfigured" {
		t.Errorf("expected Caddy 80 to be flagged unconfigured+BlockedByUFW, got %+v", evalMap[80])
	}
	if !evalMap[443].BlockedByUFW || evalMap[443].UFWStatus != "unconfigured" {
		t.Errorf("expected Caddy 443 to be flagged unconfigured+BlockedByUFW, got %+v", evalMap[443])
	}
	if evalMap[22].UFWStatus != "allowed" || evalMap[25329].UFWStatus != "allowed" {
		t.Errorf("expected SSH and Panel to be allowed, got 22=%+v 25329=%+v", evalMap[22], evalMap[25329])
	}

	// Verify AdditionalDetectedSpecs auto-generates allow specs for Caddy 80/tcp, Caddy 443/any, and Docker 8080/tcp
	managed := ManagedPortSpecs(cfg, true)
	extraSpecs := AdditionalDetectedSpecs(evaluated, existingRules, managed)
	wantExtra := []RuleSpec{
		{Action: "allow", Port: "80", Proto: "tcp", Comment: "Sys-caddy"},
		{Action: "allow", Port: "443", Proto: "any", Comment: "Sys-caddy"},
		{Action: "allow", Port: "8080", Proto: "tcp", Comment: "Sys-docker"},
	}
	if !reflect.DeepEqual(extraSpecs, wantExtra) {
		t.Fatalf("AdditionalDetectedSpecs mismatch:\ngot : %+v\nwant: %+v", extraSpecs, wantExtra)
	}

	// Verify that user-configured Cloudflare IP whitelist ("restricted") and explicit DENY ("denied") are NEVER overridden
	customRulesSample := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 25329/tcp                  ALLOW IN    Anywhere
[ 3] 39019                      ALLOW IN    Anywhere
[ 4] 2096/tcp                   ALLOW IN    Anywhere
[ 5] 80/tcp                     ALLOW IN    Anywhere                   # Sys-caddy
[ 6] 443/tcp                    ALLOW IN    173.245.48.0/20            # CF-Origin-Only
[ 7] 8080/tcp                   DENY IN     Anywhere                   # Block-8080`

	_, _, _, customRules := ParseUFWNumberedOutput(customRulesSample)
	customEval := EvaluateUFWCoverage(buildDetectedPorts(raw, owners, dockerPorts, 32768, 60999, cfg, []int{22}), customRules, true, "deny")
	customMap := make(map[int]DetectedPort)
	for _, dp := range customEval {
		customMap[dp.Port] = dp
	}
	if customMap[443].UFWStatus != "restricted" || customMap[443].BlockedByUFW {
		t.Errorf("expected Cloudflare IP-restricted 443 to have UFWStatus=restricted, got %+v", customMap[443])
	}
	if customMap[8080].UFWStatus != "denied" || !customMap[8080].BlockedByUFW {
		t.Errorf("expected explicitly denied 8080 to have UFWStatus=denied, got %+v", customMap[8080])
	}
	extraAfterCustom := AdditionalDetectedSpecs(customEval, customRules, managed)
	if len(extraAfterCustom) != 0 {
		t.Errorf("expected 0 extra auto-allow specs when 80=allowed, 443=restricted, 8080=denied, got %+v", extraAfterCustom)
	}

	// Verify annotateProtectedRules marks Caddy rules as Protected so accidental deletion prompts confirmation
	annotatedCustom := annotateProtectedRules(customRules, []int{22}, cfg, customEval)
	if !annotatedCustom[4].Protected || annotatedCustom[4].Role != "服务: caddy" {
		t.Errorf("expected rule [5] (80/tcp) to be Protected with Role='服务: caddy', got %+v", annotatedCustom[4])
	}
	if !annotatedCustom[5].Protected || annotatedCustom[5].Role != "服务: caddy" {
		t.Errorf("expected rule [6] (443/tcp) to be Protected with Role='服务: caddy', got %+v", annotatedCustom[5])
	}
	// DENY rule on 8080 must NOT be marked Protected
	if annotatedCustom[6].Protected {
		t.Errorf("expected DENY rule [7] not to be marked Protected, got %+v", annotatedCustom[6])
	}
}

func TestLiveLinuxSocketDetectionExcludesLoopback(t *testing.T) {
	extLn, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("unable to open test wildcard listener: %v", err)
	}
	defer extLn.Close()
	extPort := extLn.Addr().(*net.TCPAddr).Port

	loopLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("unable to open test loopback listener: %v", err)
	}
	defer loopLn.Close()
	loopPort := loopLn.Addr().(*net.TCPAddr).Port

	cfg := config.PanelConfig{ListenPort: 65001}
	detected := DetectListeningPorts(context.Background(), cfg, []int{22}, nil, false, "")

	foundExt := false
	foundLoop := false
	for _, dp := range detected {
		if dp.Port == extPort {
			foundExt = true
			if dp.Process == "" || dp.PID <= 0 {
				t.Errorf("expected live socket owner process & PID to be resolved via /proc/<pid>/fd, got %+v", dp)
			}
		}
		if dp.Port == loopPort {
			foundLoop = true
		}
	}
	if !foundExt {
		t.Errorf("expected live wildcard listener 0.0.0.0:%d to be detected in DetectListeningPorts, got %+v", extPort, detected)
	}
	if foundLoop {
		t.Errorf("expected live loopback listener 127.0.0.1:%d to be excluded from DetectListeningPorts", loopPort)
	}
}
