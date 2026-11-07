package firewall

import (
	"encoding/hex"
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
