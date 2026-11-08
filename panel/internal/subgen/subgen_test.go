package subgen

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

func TestSpeedtestProcessRegexMatchesLatestBinaries(t *testing.T) {
	clientRe := regexp.MustCompile(suohaClientProcessRegex)
	cfstRe := regexp.MustCompile(cfstEngineProcessRegex)

	// Exact binary names from .github/workflows/release-client.yml, client_scripts.go, and manual builds
	mustMatchClient := []string{
		"suoha-client",
		"suoha-client.exe",
		"suoha-client-darwin-arm64",
		"suoha-client-darwin-amd64",
		"suoha-client-windows-amd64.exe",
		"suoha-client-windows-arm64.exe",
		"suoha-client-linux-amd64",
		"suoha-client-linux-arm64",
		"suoha-client-linux-armv7",
		"suoha-client-linux-386",
		"suoha-client-windows-amd64 (1).exe", // browser duplicate download suffix
		"suoha-client-li",                    // 15-char Linux /proc/<pid>/comm truncation
	}
	for _, name := range mustMatchClient {
		if !clientRe.MatchString(name) {
			t.Errorf("suohaClientProcessRegex failed to match %q", name)
		}
	}

	// Exact cfst binaries from client/main.go (cfst_<os>_<arch>.zip/.tar.gz & legacy candidates)
	mustMatchCfst := []string{
		"cfst",
		"cfst.exe",
		"CloudflareSpeedTest",
		"CloudflareSpeedTest.exe",
		"CloudflareST",
		"CloudflareST.exe",
	}
	for _, name := range mustMatchCfst {
		if !cfstRe.MatchString(name) {
			t.Errorf("cfstEngineProcessRegex failed to match %q", name)
		}
	}

	// Unrelated processes must NOT match
	for _, other := range []string{"chrome.exe", "curl", "mihomo", "cloudflare-warp.exe", "xray"} {
		if clientRe.MatchString(other) || cfstRe.MatchString(other) {
			t.Errorf("process bypass regex falsely matched unrelated binary %q", other)
		}
	}
}

func TestSmartRoutingClashYAMLWithNodes(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Protocols.IPv6SSEnabled = true
		d.Protocols.IPv6Addr = "2400:cb00::8888"
		d.Protocols.SSPort = 35000
		d.Protocols.ServerHostOverride = "vps.example.com"
		return nil
	})
	_, _ = store.SetPreferredIPs([]config.PreferredIP{
		{IP: "104.16.8.8", Port: 2053, Colo: "HKG", Latency: "28ms", Label: "优选1-HKG-28ms"},
	}, "client")

	rt := RuntimeState{
		ArgoVL:    "smart-test.trycloudflare.com",
		ArgoTR:    "smart-test.trycloudflare.com",
		ArgoPanel: "smart-test.trycloudflare.com",
		ServerIP:  "1.2.3.4",
	}

	bundle := Generate(store.GetConfig(), store.GetPreferred(), rt)
	yml := bundle.ClashYAML

	// 1. Global cross-client safe settings + speedtest & server self-protection rules
	for _, mustHave := range []string{
		"mixed-port: 7890",
		"socks-port: 7891",
		"ipv6: true",
		"unified-delay: true",
		"tcp-concurrent: true",
		"find-process-mode: strict",
		"store-selected: true",
		"store-fake-ip: true",
		"sniffer:",
		"enhanced-mode: fake-ip",
		"respect-rules: true",
		"prefer-h3: false",
		"proxy-server-nameserver:",
		"direct-nameserver:",
		"https://cloudflare-dns.com/dns-query",
		"client-fingerprint: chrome",
		"PROCESS-NAME-REGEX,(?i)^suoha-client,DIRECT",
		"DOMAIN,vps.example.com," + GroupServer,
		"DOMAIN,smart-test.trycloudflare.com," + GroupServer,
		"IP-CIDR,1.2.3.4/32," + GroupServer + ",no-resolve",
		"IP-CIDR6,2400:cb00::8888/128," + GroupServer + ",no-resolve",
	} {
		if !strings.Contains(yml, mustHave) {
			t.Errorf("clash.yaml missing expected line/fragment %q", mustHave)
		}
	}

	// Ensure TUN and external-controller are not hardcoded in remote subscription
	if strings.Contains(yml, "\ntun:") || strings.Contains(yml, "external-controller:") {
		t.Errorf("clash.yaml should not hardcode tun or external-controller in remote subscription")
	}

	// 2. Verify structural integrity of proxies, proxy-groups, rule-providers, and rules
	verifyClashStructure(t, yml, true)

	// 3. Verify critical rule ordering invariants
	assertRawOrder := func(earlier, later string) {
		t.Helper()
		idx1 := strings.Index(yml, earlier)
		idx2 := strings.Index(yml, later)
		if idx1 < 0 || idx2 < 0 {
			t.Fatalf("missing rule(s) in order check: %q (idx=%d), %q (idx=%d)", earlier, idx1, later, idx2)
		}
		if idx1 >= idx2 {
			t.Errorf("expected %q (pos %d) to appear BEFORE %q (pos %d)", earlier, idx1, later, idx2)
		}
	}

	assertRawOrder("PROCESS-NAME-REGEX,(?i)^suoha-client,DIRECT", "  - RULE-SET,private_domain,")
	assertRawOrder("  - RULE-SET,private_ip,DIRECT,no-resolve", "  - DOMAIN,smart-test.trycloudflare.com,"+GroupServer)
	assertRawOrder("  - IP-CIDR,1.2.3.4/32,"+GroupServer+",no-resolve", "  - RULE-SET,ads_domain,")

	assertRuleOrder := func(earlier, later string) {
		t.Helper()
		assertRawOrder("  - RULE-SET,"+earlier+",", "  - RULE-SET,"+later+",")
	}

	assertRuleOrder("private_domain", "ads_domain")
	assertRuleOrder("ads_domain", "ai_domain")
	assertRuleOrder("ai_domain", "google_domain")
	assertRuleOrder("ai_domain", "microsoft_domain")
	assertRuleOrder("github_domain", "microsoft_domain")
	assertRuleOrder("youtube_domain", "google_domain")
	assertRuleOrder("biliintl_domain", "bilibili_domain")
	assertRuleOrder("steam_cn_domain", "steam_domain")
	assertRuleOrder("games_cn_domain", "steam_domain")
	assertRuleOrder("apple_cn_domain", "apple_domain")
	assertRuleOrder("microsoft_cn_domain", "microsoft_domain")
	assertRuleOrder("geolocation_not_cn", "cn_domain")
	assertRuleOrder("cn_domain", "cn_ip")

	if !strings.Contains(yml, "  - MATCH,"+GroupFinal+"\n") {
		t.Errorf("expected final fallback rule MATCH,%s", GroupFinal)
	}
}

func TestSmartRoutingClashYAMLZeroNodes(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}

	// Empty RuntimeState and IPv6SSEnabled=false -> 0 active nodes; loopback/private IPs ignored
	bundle := Generate(store.GetConfig(), store.GetPreferred(), RuntimeState{ServerIP: "127.0.0.1"})
	yml := bundle.ClashYAML

	if len(bundle.Nodes) != 0 {
		t.Fatalf("expected 0 nodes when tunnel is not running, got %d", len(bundle.Nodes))
	}
	if !strings.Contains(yml, "proxies: []") {
		t.Errorf("expected explicit empty proxies: [] when 0 nodes")
	}
	if !strings.Contains(yml, "respect-rules: false") {
		t.Errorf("expected respect-rules: false when 0 nodes")
	}
	if strings.Contains(yml, "https://cloudflare-dns.com/dns-query") {
		t.Errorf("expected domestic DoH fallback in nameserver when 0 nodes")
	}
	if strings.Contains(yml, "127.0.0.1/32") {
		t.Errorf("loopback IP should not be emitted as Server IP-CIDR rule")
	}

	verifyClashStructure(t, yml, false)
}

func TestRealityDirectStandaloneAndCoexistence(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}

	// Default SNI must be Apple domain www.apple.com
	initCfg := store.GetConfig()
	if initCfg.Protocols.RealitySNI != "www.apple.com" {
		t.Fatalf("expected default RealitySNI 'www.apple.com', got %q", initCfg.Protocols.RealitySNI)
	}

	// 1. Standalone VLESS + Reality + XTLS-RPRX-Vision (no Argo tunnel)
	cfgStandalone, err := store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Tunnel.Enabled = false
		d.Protocols.RealityEnabled = true
		d.Protocols.RealityPort = 24443
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	standalone := Generate(cfgStandalone, store.GetPreferred(), RuntimeState{
		ServerIP: "198.51.100.77",
	})
	if len(standalone.Nodes) != 1 {
		t.Fatalf("expected 1 standalone Reality node, got %d", len(standalone.Nodes))
	}
	rNode := standalone.Nodes[0]
	if rNode.Protocol != "reality" {
		t.Errorf("expected protocol 'reality', got %q", rNode.Protocol)
	}
	for _, frag := range []string{
		"vless://" + cfgStandalone.Protocols.UUID + "@198.51.100.77:24443?",
		"flow=xtls-rprx-vision",
		"security=reality",
		"sni=www.apple.com",
		"fp=chrome",
		"pbk=" + cfgStandalone.Protocols.RealityPublicKey,
		"sid=" + cfgStandalone.Protocols.RealityShortID,
		"type=tcp",
	} {
		if !strings.Contains(rNode.URI, frag) {
			t.Errorf("Reality URI missing %q:\n%s", frag, rNode.URI)
		}
	}
	for _, ymlFrag := range []string{
		"type: vless",
		"flow: xtls-rprx-vision",
		`servername: "www.apple.com"`,
		`client-fingerprint: "chrome"`,
		"reality-opts:",
		fmt.Sprintf("public-key: %q", cfgStandalone.Protocols.RealityPublicKey),
		fmt.Sprintf("short-id: %q", cfgStandalone.Protocols.RealityShortID),
		"support-x25519mlkem768: true",
		"IP-CIDR,198.51.100.77/32,Server-服务器运维,no-resolve",
	} {
		if !strings.Contains(standalone.ClashYAML, ymlFrag) {
			t.Errorf("standalone ClashYAML missing %q:\n%s", ymlFrag, standalone.ClashYAML)
		}
	}
	verifyClashStructure(t, standalone.ClashYAML, true)

	// 2. Coexistence with custom SNI + Argo VLESS-WS + Trojan-WS + IPv6 SS
	cfgCoexist, err := store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Tunnel.Enabled = true
		d.Protocols.RealityEnabled = true
		d.Protocols.RealitySNI = "itunes.apple.com"
		d.Protocols.RealityFingerprint = "safari"
		d.Protocols.IPv6SSEnabled = true
		d.Protocols.IPv6Addr = "2001:db8::99"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	coexist := Generate(cfgCoexist, store.GetPreferred(), RuntimeState{
		ArgoVL:   "vl-coexist.trycloudflare.com",
		ArgoTR:   "tr-coexist.trycloudflare.com",
		ServerIP: "198.51.100.77",
	})
	if len(coexist.Nodes) < 4 {
		t.Fatalf("expected Reality + VLESS + Trojan + SS coexistence nodes, got %d", len(coexist.Nodes))
	}
	if coexist.Nodes[0].Protocol != "reality" || !strings.Contains(coexist.Nodes[0].URI, "sni=itunes.apple.com") || !strings.Contains(coexist.Nodes[0].URI, "fp=safari") {
		t.Errorf("expected first node to be Reality with custom SNI itunes.apple.com and fp=safari, got %+v", coexist.Nodes[0])
	}
	if strings.Contains(coexist.ClashYAML, `client-fingerprint: "safari"`) || !strings.Contains(coexist.ClashYAML, "support-x25519mlkem768: true") {
		t.Errorf("expected coexist ClashYAML to pin Reality client-fingerprint to chrome and enable support-x25519mlkem768:\n%s", coexist.ClashYAML)
	}
	verifyClashStructure(t, coexist.ClashYAML, true)
}

func verifyClashStructure(t *testing.T, yml string, expectAutoGroups bool) {
	t.Helper()

	definedProxies := map[string]bool{
		"DIRECT": true,
		"REJECT": true,
	}
	definedGroups := map[string]bool{}
	groupMembers := map[string][]string{}
	definedProviders := map[string]string{} // name -> behavior

	lines := strings.Split(yml, "\n")
	section := ""
	currentGroup := ""
	currentProvider := ""

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = strings.TrimSuffix(trimmed, ":")
			if strings.HasPrefix(trimmed, "proxies:") {
				section = "proxies"
			}
			currentGroup = ""
			currentProvider = ""
			continue
		}

		switch section {
		case "proxies":
			if strings.HasPrefix(line, "  - name: ") {
				name := unquoteYAML(strings.TrimPrefix(line, "  - name: "))
				definedProxies[name] = true
			}
		case "proxy-groups":
			if strings.HasPrefix(line, "  - name: ") {
				currentGroup = unquoteYAML(strings.TrimPrefix(line, "  - name: "))
				if definedGroups[currentGroup] {
					t.Errorf("duplicate proxy-group %q", currentGroup)
				}
				definedGroups[currentGroup] = true
			} else if currentGroup != "" && strings.HasPrefix(line, "      - ") {
				member := unquoteYAML(strings.TrimPrefix(line, "      - "))
				groupMembers[currentGroup] = append(groupMembers[currentGroup], member)
			}
		case "rule-providers":
			if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
				currentProvider = strings.TrimSuffix(trimmed, ":")
				if _, exists := definedProviders[currentProvider]; exists {
					t.Errorf("duplicate rule-provider %q", currentProvider)
				}
				definedProviders[currentProvider] = ""
			} else if currentProvider != "" && strings.HasPrefix(line, "    behavior: ") {
				definedProviders[currentProvider] = strings.TrimSpace(strings.TrimPrefix(line, "    behavior: "))
			} else if currentProvider != "" && strings.HasPrefix(line, "    proxy: ") {
				p := unquoteYAML(strings.TrimPrefix(line, "    proxy: "))
				if !definedProxies[p] && !definedGroups[p] {
					t.Errorf("rule-provider %q references undefined proxy/group %q", currentProvider, p)
				}
			}
		case "rules":
			if strings.HasPrefix(line, "  - ") {
				rule := unquoteYAML(strings.TrimPrefix(line, "  - "))
				parts := strings.Split(rule, ",")
				switch parts[0] {
				case "PROCESS-NAME", "PROCESS-NAME-REGEX", "DOMAIN", "DOMAIN-SUFFIX":
					if len(parts) != 3 {
						t.Errorf("malformed %s rule: %q", parts[0], rule)
						continue
					}
					target := parts[2]
					if !definedProxies[target] && !definedGroups[target] {
						t.Errorf("%s rule references undefined target %q: %q", parts[0], target, rule)
					}
				case "IP-CIDR", "IP-CIDR6":
					if len(parts) < 4 || parts[3] != "no-resolve" {
						t.Errorf("%s rule must carry no-resolve: %q", parts[0], rule)
						continue
					}
					target := parts[2]
					if !definedProxies[target] && !definedGroups[target] {
						t.Errorf("%s rule references undefined target %q: %q", parts[0], target, rule)
					}
				case "RULE-SET":
					if len(parts) < 3 {
						t.Errorf("malformed RULE-SET rule: %q", rule)
						continue
					}
					prov, target := parts[1], parts[2]
					behavior, ok := definedProviders[prov]
					if !ok {
						t.Errorf("RULE-SET references undefined provider %q in rule %q", prov, rule)
					}
					if !definedProxies[target] && !definedGroups[target] {
						t.Errorf("RULE-SET references undefined target %q in rule %q", target, rule)
					}
					if behavior == "ipcidr" {
						if len(parts) < 4 || parts[3] != "no-resolve" {
							t.Errorf("ipcidr RULE-SET %q must carry no-resolve: %q", prov, rule)
						}
					}
				case "MATCH":
					if len(parts) != 2 {
						t.Errorf("malformed MATCH rule: %q", rule)
						continue
					}
					target := parts[1]
					if !definedProxies[target] && !definedGroups[target] {
						t.Errorf("MATCH references undefined target %q", target)
					}
				default:
					t.Errorf("unexpected rule type %q in rule %q", parts[0], rule)
				}
			}
		}
	}

	// Verify expected groups exist
	requiredGroups := []string{
		GroupProxy, GroupAI, GroupYouTube, GroupGoogle, GroupStreaming,
		GroupSocial, GroupGitHub, GroupGaming, GroupApple, GroupMicrosoft,
		GroupServer, GroupAdBlock, GroupCN, GroupFinal,
	}
	if expectAutoGroups {
		requiredGroups = append(requiredGroups, GroupAuto, GroupFallback)
	}
	for _, g := range requiredGroups {
		if !definedGroups[g] {
			t.Errorf("missing expected proxy-group %q", g)
		}
	}
	if !expectAutoGroups && (definedGroups[GroupAuto] || definedGroups[GroupFallback]) {
		t.Errorf("url-test/fallback groups should not be emitted when 0 proxy nodes exist")
	}

	// Server-服务器运维 must default to DIRECT as its first option
	if srvMembers := groupMembers[GroupServer]; len(srvMembers) == 0 || srvMembers[0] != "DIRECT" {
		t.Errorf("expected %s to default to DIRECT first, got %v", GroupServer, srvMembers)
	}

	// Verify every member of every proxy-group resolves to a valid proxy or proxy-group
	for g, members := range groupMembers {
		if len(members) == 0 {
			t.Errorf("proxy-group %q has empty proxies list", g)
		}
		for _, m := range members {
			if !definedProxies[m] && !definedGroups[m] {
				t.Errorf("proxy-group %q references undefined proxy/group %q", g, m)
			}
		}
	}

	// Verify all rule-set:<name> references inside dns section exist in rule-providers
	for _, line := range lines {
		idx := strings.Index(line, "rule-set:")
		if idx < 0 {
			continue
		}
		rest := line[idx+len("rule-set:"):]
		end := strings.IndexAny(rest, `":' `)
		if end >= 0 {
			rest = rest[:end]
		}
		for _, name := range strings.Split(rest, ",") {
			if _, ok := definedProviders[name]; !ok {
				t.Errorf("dns section references undefined rule-provider %q in line %q", name, line)
			}
		}
	}

	verifyOptionalPythonYAML(t, yml)
}

func verifyOptionalPythonYAML(t *testing.T, yml string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		return
	}
	if err := exec.Command(py, "-c", "import yaml").Run(); err != nil {
		return
	}
	script := `
import sys, yaml
doc = yaml.safe_load(sys.stdin.read())
assert isinstance(doc, dict), "root must be mapping"
for k in ("mixed-port", "socks-port", "mode", "sniffer", "dns", "proxies", "proxy-groups", "rule-providers", "rules"):
    assert k in doc, f"missing key {k}"
assert len(doc["rule-providers"]) == 34, f"unexpected rule-providers count: {len(doc['rule-providers'])}"
assert doc["rules"][0] == "PROCESS-NAME-REGEX,(?i)^suoha-client,DIRECT", f"unexpected rule[0]: {doc['rules'][0]}"
assert doc["rules"][1] == r"PROCESS-NAME-REGEX,(?i)^(cfst|cloudflarespeedtest|cloudflarest)(\.exe)?$,DIRECT", f"unexpected rule[1]: {doc['rules'][1]}"
for p in doc["proxies"]:
    if "reality-opts" in p:
        assert p.get("client-fingerprint") == "chrome", f"Reality client-fingerprint must be chrome, got {p.get('client-fingerprint')}"
        assert p["reality-opts"].get("support-x25519mlkem768") is True, f"Reality missing support-x25519mlkem768: true in {p}"
`
	cmd := exec.Command(py, "-c", script)
	cmd.Stdin = strings.NewReader(yml)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strict PyYAML parse failed: %v\n%s", err, string(out))
	}
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		s = s[1 : len(s)-1]
	}
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}
