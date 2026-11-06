package subgen

import (
	"fmt"
	"net"
	"strings"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

const (
	metaRulesBaseURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta"
	healthCheckURL   = "https://www.gstatic.com/generate_204"

	// Core strategy group names (keep PROXY and AUTO-优选自动测速 stable for compatibility).
	GroupProxy     = "PROXY"
	GroupAuto      = "AUTO-优选自动测速"
	GroupFallback  = "FALLBACK-故障转移"
	GroupAI        = "AI-人工智能"
	GroupYouTube   = "YouTube"
	GroupGoogle    = "Google"
	GroupStreaming = "Streaming-流媒体"
	GroupSocial    = "Telegram-社交通讯"
	GroupGitHub    = "GitHub-开发者"
	GroupGaming    = "Gaming-游戏平台"
	GroupApple     = "Apple-苹果服务"
	GroupMicrosoft = "Microsoft-微软服务"
	GroupServer    = "Server-服务器运维"
	GroupAdBlock   = "AdBlock-广告拦截"
	GroupCN        = "CN-国内直连"
	GroupFinal     = "FINAL-漏网之鱼"

	// Direct bypass process regexes for local preferred-IP speedtesting (prevents TUN mode hijacking):
	//   1) suoha-client Release/bootstrap binaries: suoha-client-{darwin,linux,windows}-{amd64,arm64,armv7,386}[.exe] & suoha-client[.exe]
	//   2) XIU2 CloudflareSpeedTest engine binaries: cfst[.exe], CloudflareSpeedTest[.exe], CloudflareST[.exe]
	suohaClientProcessRegex = `(?i)^suoha-client`
	cfstEngineProcessRegex  = `(?i)^(cfst|cloudflarespeedtest|cloudflarest)(\.exe)?$`
)

type clashRuleProvider struct {
	Name     string
	Behavior string // "domain" | "ipcidr"
	Path     string // relative path under MetaCubeX/meta-rules-dat meta branch
}

type clashRuleEntry struct {
	Provider  string
	Target    string
	NoResolve bool
}

type serverSelfTargets struct {
	Domains   []string
	IPv4CIDRs []string
	IPv6CIDRs []string
}

// Ordered MetaCubeX .mrs binary rule-providers (domain & ipcidr).
var builtinRuleProviders = []clashRuleProvider{
	// Domain rule-sets (geosite)
	{Name: "private_domain", Behavior: "domain", Path: "geo/geosite/private.mrs"},
	{Name: "ads_domain", Behavior: "domain", Path: "geo/geosite/category-ads-all.mrs"},
	{Name: "ai_domain", Behavior: "domain", Path: "geo/geosite/category-ai-!cn.mrs"},
	{Name: "github_domain", Behavior: "domain", Path: "geo/geosite/github.mrs"},
	{Name: "youtube_domain", Behavior: "domain", Path: "geo/geosite/youtube.mrs"},
	{Name: "google_domain", Behavior: "domain", Path: "geo/geosite/google.mrs"},
	{Name: "telegram_domain", Behavior: "domain", Path: "geo/geosite/telegram.mrs"},
	{Name: "twitter_domain", Behavior: "domain", Path: "geo/geosite/twitter.mrs"},
	{Name: "discord_domain", Behavior: "domain", Path: "geo/geosite/discord.mrs"},
	{Name: "facebook_domain", Behavior: "domain", Path: "geo/geosite/facebook.mrs"},
	{Name: "netflix_domain", Behavior: "domain", Path: "geo/geosite/netflix.mrs"},
	{Name: "disney_domain", Behavior: "domain", Path: "geo/geosite/disney.mrs"},
	{Name: "tiktok_domain", Behavior: "domain", Path: "geo/geosite/tiktok.mrs"},
	{Name: "spotify_domain", Behavior: "domain", Path: "geo/geosite/spotify.mrs"},
	{Name: "bahamut_domain", Behavior: "domain", Path: "geo/geosite/bahamut.mrs"},
	{Name: "biliintl_domain", Behavior: "domain", Path: "geo/geosite/biliintl.mrs"},
	{Name: "bilibili_domain", Behavior: "domain", Path: "geo/geosite/bilibili.mrs"},
	{Name: "steam_cn_domain", Behavior: "domain", Path: "geo/geosite/steam@cn.mrs"},
	{Name: "games_cn_domain", Behavior: "domain", Path: "geo/geosite/category-games@cn.mrs"},
	{Name: "steam_domain", Behavior: "domain", Path: "geo/geosite/steam.mrs"},
	{Name: "apple_cn_domain", Behavior: "domain", Path: "geo/geosite/apple-cn.mrs"},
	{Name: "apple_domain", Behavior: "domain", Path: "geo/geosite/apple.mrs"},
	{Name: "microsoft_cn_domain", Behavior: "domain", Path: "geo/geosite/microsoft@cn.mrs"},
	{Name: "onedrive_domain", Behavior: "domain", Path: "geo/geosite/onedrive.mrs"},
	{Name: "microsoft_domain", Behavior: "domain", Path: "geo/geosite/microsoft.mrs"},
	{Name: "geolocation_not_cn", Behavior: "domain", Path: "geo/geosite/geolocation-!cn.mrs"},
	{Name: "cn_domain", Behavior: "domain", Path: "geo/geosite/cn.mrs"},

	// IP-CIDR rule-sets (geoip)
	{Name: "private_ip", Behavior: "ipcidr", Path: "geo/geoip/private.mrs"},
	{Name: "google_ip", Behavior: "ipcidr", Path: "geo/geoip/google.mrs"},
	{Name: "netflix_ip", Behavior: "ipcidr", Path: "geo/geoip/netflix.mrs"},
	{Name: "telegram_ip", Behavior: "ipcidr", Path: "geo/geoip/telegram.mrs"},
	{Name: "twitter_ip", Behavior: "ipcidr", Path: "geo/geoip/twitter.mrs"},
	{Name: "facebook_ip", Behavior: "ipcidr", Path: "geo/geoip/facebook.mrs"},
	{Name: "cn_ip", Behavior: "ipcidr", Path: "geo/geoip/cn.mrs"},
}

// Ordered Rule-Set entries applied after process bypass, LAN/private bypass, and server self-access rules:
//   - AdBlock before app rules
//   - AI before Google & Microsoft (so Gemini / Copilot obey AI group)
//   - GitHub before Microsoft (geosite:microsoft includes github)
//   - YouTube before Google (geosite:google includes youtube)
//   - Domestic game/CDN overrides before Steam/global rules
//   - geolocation_not_cn before cn_domain (avoids bare .cn TLD hijacking non-CN services)
//   - All IP-CIDR rules carry no-resolve to prevent local DNS leaks
var postServerRuleEntries = []clashRuleEntry{
	// 1. Ad & tracker blocking
	{Provider: "ads_domain", Target: GroupAdBlock},

	// 2. Overseas AI services (ChatGPT / Claude / Gemini / Copilot / Perplexity)
	{Provider: "ai_domain", Target: GroupAI},

	// 3. Developer & Google ecosystem
	{Provider: "github_domain", Target: GroupGitHub},
	{Provider: "youtube_domain", Target: GroupYouTube},
	{Provider: "google_domain", Target: GroupGoogle},

	// 4. Telegram & overseas social networks
	{Provider: "telegram_domain", Target: GroupSocial},
	{Provider: "twitter_domain", Target: GroupSocial},
	{Provider: "discord_domain", Target: GroupSocial},
	{Provider: "facebook_domain", Target: GroupSocial},

	// 5. Global streaming media
	{Provider: "netflix_domain", Target: GroupStreaming},
	{Provider: "disney_domain", Target: GroupStreaming},
	{Provider: "tiktok_domain", Target: GroupStreaming},
	{Provider: "spotify_domain", Target: GroupStreaming},
	{Provider: "bahamut_domain", Target: GroupStreaming},
	{Provider: "biliintl_domain", Target: GroupStreaming},

	// 6. Mainland video & game download CDNs (direct high-speed bypass)
	{Provider: "bilibili_domain", Target: GroupCN},
	{Provider: "steam_cn_domain", Target: GroupCN},
	{Provider: "games_cn_domain", Target: GroupCN},

	// 7. Overseas gaming platforms
	{Provider: "steam_domain", Target: GroupGaming},

	// 8. Apple & Microsoft (CN direct first, then global policy group)
	{Provider: "apple_cn_domain", Target: GroupCN},
	{Provider: "apple_domain", Target: GroupApple},
	{Provider: "microsoft_cn_domain", Target: GroupCN},
	{Provider: "onedrive_domain", Target: GroupMicrosoft},
	{Provider: "microsoft_domain", Target: GroupMicrosoft},

	// 9. General overseas vs Mainland China domains
	{Provider: "geolocation_not_cn", Target: GroupProxy},
	{Provider: "cn_domain", Target: GroupCN},

	// 10. IP-CIDR rules (all with no-resolve to avoid local DNS queries)
	{Provider: "google_ip", Target: GroupGoogle, NoResolve: true},
	{Provider: "netflix_ip", Target: GroupStreaming, NoResolve: true},
	{Provider: "telegram_ip", Target: GroupSocial, NoResolve: true},
	{Provider: "twitter_ip", Target: GroupSocial, NoResolve: true},
	{Provider: "facebook_ip", Target: GroupSocial, NoResolve: true},
	{Provider: "cn_ip", Target: GroupCN, NoResolve: true},
}

var fakeIPFilterItems = []string{
	"*.lan",
	"+.lan",
	"+.local",
	"+.localdomain",
	"+.home.arpa",
	"+.arpa",
	"localhost.ptlogin2.qq.com",
	"localhost.sec.qq.com",
	"+.msftconnecttest.com",
	"+.msftncsi.com",
	"connectivitycheck.gstatic.com",
	"captive.apple.com",
	"time.*.com",
	"time.*.gov",
	"ntp.*.com",
	"+.pool.ntp.org",
	"+.stun.*.*",
	"+.stun.*.*.*",
	"+.market.xiaomi.com",
	"Mijia Cloud",
	"rule-set:private_domain",
	"rule-set:cn_domain",
}

// extractServerTargets collects deduplicated public IPs and panel/subscription domains of the deployment server.
func extractServerTargets(cfg config.PanelConfig, rt RuntimeState) serverSelfTargets {
	var out serverSelfTargets
	seenDom := make(map[string]bool)
	seenV4 := make(map[string]bool)
	seenV6 := make(map[string]bool)

	candidates := []string{
		cfg.Protocols.ServerHostOverride,
		rt.ServerIP,
		cfg.Protocols.IPv6Addr,
		rt.ArgoPanel,
	}
	if cfg.Tunnel.Mode == "token" {
		candidates = append(candidates, cfg.Tunnel.CustomDomain)
	}

	for _, raw := range candidates {
		h := cleanRawHost(raw)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				cidr := ip4.String() + "/32"
				if !seenV4[cidr] {
					seenV4[cidr] = true
					out.IPv4CIDRs = append(out.IPv4CIDRs, cidr)
				}
			} else {
				cidr := ip.String() + "/128"
				if !seenV6[cidr] {
					seenV6[cidr] = true
					out.IPv6CIDRs = append(out.IPv6CIDRs, cidr)
				}
			}
			continue
		}
		if config.IsValidHostOrIP(h) && strings.Contains(h, ".") && !strings.EqualFold(h, "localhost") {
			dom := strings.ToLower(h)
			if !seenDom[dom] {
				seenDom[dom] = true
				out.Domains = append(out.Domains, dom)
			}
		}
	}
	return out
}

// buildClashYAML renders a complete Mihomo / Clash Meta YAML configuration with:
//   - Sniffer (HTTP/TLS/QUIC domain sniffing)
//   - Anti-DNS-leak split DNS (Fake-IP + respect-rules + domestic/overseas DoH split)
//   - Multi-scene proxy-groups (AUTO url-test, FALLBACK, AI, Streaming, Social, Gaming, Server, etc.)
//   - Local speedtest direct bypass (suoha-client-* & cfst / CloudflareSpeedTest)
//   - Deployment server self-access protection (avoids SSH/panel self-disconnect & subscription deadlock)
//   - MetaCubeX binary .mrs rule-providers & strictly ordered routing rules
func buildClashYAML(proxyLines []string, proxyNames []string, cfg config.PanelConfig, rt RuntimeState) string {
	hasProxies := len(proxyNames) > 0
	srvTargets := extractServerTargets(cfg, rt)
	var lines []string

	// 1. Global settings (cross-client safe; leaves TUN/API controller to GUI client)
	lines = append(lines,
		"# New-Suoha Mihomo / Clash Meta Smart Routing Configuration",
		"mixed-port: 7890",
		"socks-port: 7891",
		"allow-lan: false",
		`bind-address: "*"`,
		"mode: rule",
		"log-level: info",
		"ipv6: true",
		"unified-delay: true",
		"tcp-concurrent: true",
		"find-process-mode: strict",
		"profile:",
		"  store-selected: true",
		"  store-fake-ip: true",
		"",
	)

	// 2. Domain sniffer (recovers domain routing for hardcoded-IP clients without overriding CDN preferred IPs)
	lines = append(lines,
		"sniffer:",
		"  enable: true",
		"  force-dns-mapping: true",
		"  parse-pure-ip: true",
		"  override-destination: false",
		"  sniff:",
		"    HTTP:",
		"      ports: [80, 8080-8880]",
		"      override-destination: true",
		"    TLS:",
		"      ports: [443, 8443]",
		"    QUIC:",
		"      ports: [443, 8443]",
		"  skip-domain:",
		`    - "Mijia Cloud"`,
		`    - "+.push.apple.com"`,
		`    - "dlg.io.mi.com"`,
		"",
	)

	// 3. Anti-DNS-leak split DNS configuration
	respectRules := "false"
	if hasProxies {
		respectRules = "true"
	}
	lines = append(lines,
		"dns:",
		"  enable: true",
		"  cache-algorithm: arc",
		"  prefer-h3: false",
		"  ipv6: true",
		"  use-hosts: true",
		"  use-system-hosts: true",
		"  respect-rules: "+respectRules,
		"  enhanced-mode: fake-ip",
		"  fake-ip-range: 198.18.0.1/16",
		"  fake-ip-filter-mode: blacklist",
		"  fake-ip-filter:",
	)
	for _, item := range fakeIPFilterItems {
		lines = append(lines, "    - "+yamlQuote(item))
	}
	lines = append(lines,
		"  default-nameserver:",
		"    - 223.5.5.5",
		"    - 119.29.29.29",
		"  proxy-server-nameserver:",
		"    - https://dns.alidns.com/dns-query",
		"    - https://doh.pub/dns-query",
		"  direct-nameserver:",
		"    - https://dns.alidns.com/dns-query",
		"    - https://doh.pub/dns-query",
	)
	if hasProxies {
		lines = append(lines,
			"  nameserver:",
			"    - https://cloudflare-dns.com/dns-query",
			"    - https://dns.google/dns-query",
		)
	} else {
		lines = append(lines,
			"  nameserver:",
			"    - https://dns.alidns.com/dns-query",
			"    - https://doh.pub/dns-query",
		)
	}
	lines = append(lines,
		"  nameserver-policy:",
		`    "rule-set:private_domain":`,
		"      - https://dns.alidns.com/dns-query",
		"      - https://doh.pub/dns-query",
		`    "rule-set:cn_domain":`,
		"      - https://dns.alidns.com/dns-query",
		"      - https://doh.pub/dns-query",
		"",
	)

	// 4. Outbound proxy nodes
	if len(proxyLines) == 0 {
		lines = append(lines, "proxies: []", "")
	} else {
		lines = append(lines, "proxies:")
		lines = append(lines, proxyLines...)
		lines = append(lines, "")
	}

	// 5. Smart routing proxy-groups
	lines = append(lines, "proxy-groups:")

	var overseasOpts []string
	var domesticOpts []string
	var serverOpts []string
	if hasProxies {
		// Entry PROXY group
		proxyEntryOpts := make([]string, 0, 2+len(proxyNames)+1)
		proxyEntryOpts = append(proxyEntryOpts, GroupAuto, GroupFallback)
		proxyEntryOpts = append(proxyEntryOpts, proxyNames...)
		proxyEntryOpts = append(proxyEntryOpts, "DIRECT")
		appendSelectGroup(&lines, GroupProxy, proxyEntryOpts)

		// Health-check groups: AUTO url-test & FALLBACK
		appendURLTestGroup(&lines, GroupAuto, "url-test", proxyNames, 50)
		appendURLTestGroup(&lines, GroupFallback, "fallback", proxyNames, 0)

		overseasOpts = make([]string, 0, 3+len(proxyNames)+1)
		overseasOpts = append(overseasOpts, GroupProxy, GroupAuto, GroupFallback)
		overseasOpts = append(overseasOpts, proxyNames...)
		overseasOpts = append(overseasOpts, "DIRECT")

		domesticOpts = []string{"DIRECT", GroupProxy, GroupAuto}

		serverOpts = make([]string, 0, 4+len(proxyNames))
		serverOpts = append(serverOpts, "DIRECT", GroupProxy, GroupAuto, GroupFallback)
		serverOpts = append(serverOpts, proxyNames...)
	} else {
		appendSelectGroup(&lines, GroupProxy, []string{"DIRECT"})
		overseasOpts = []string{GroupProxy, "DIRECT"}
		domesticOpts = []string{"DIRECT", GroupProxy}
		serverOpts = []string{"DIRECT", GroupProxy}
	}

	// Scene policy groups
	appendSelectGroup(&lines, GroupAI, overseasOpts)
	appendSelectGroup(&lines, GroupYouTube, overseasOpts)
	appendSelectGroup(&lines, GroupGoogle, overseasOpts)
	appendSelectGroup(&lines, GroupStreaming, overseasOpts)
	appendSelectGroup(&lines, GroupSocial, overseasOpts)
	appendSelectGroup(&lines, GroupGitHub, overseasOpts)
	appendSelectGroup(&lines, GroupGaming, overseasOpts)
	appendSelectGroup(&lines, GroupApple, domesticOpts)
	appendSelectGroup(&lines, GroupMicrosoft, domesticOpts)
	appendSelectGroup(&lines, GroupServer, serverOpts)
	appendSelectGroup(&lines, GroupAdBlock, []string{"REJECT", "DIRECT"})
	appendSelectGroup(&lines, GroupCN, domesticOpts)
	appendSelectGroup(&lines, GroupFinal, overseasOpts)
	lines = append(lines, "")

	// 6. MetaCubeX .mrs binary rule-providers
	providerProxy := "DIRECT"
	if hasProxies {
		providerProxy = GroupProxy
	}
	lines = append(lines, "rule-providers:")
	for _, rp := range builtinRuleProviders {
		lines = append(lines,
			fmt.Sprintf("  %s:", rp.Name),
			"    type: http",
			fmt.Sprintf("    behavior: %s", rp.Behavior),
			"    format: mrs",
			"    interval: 86400",
			fmt.Sprintf("    proxy: %s", yamlQuote(providerProxy)),
			fmt.Sprintf("    path: ./ruleset/%s.mrs", rp.Name),
			fmt.Sprintf("    url: %s", yamlQuote(metaRulesBaseURL+"/"+rp.Path)),
		)
	}
	lines = append(lines, "")

	// 7. Ordered routing rules
	lines = append(lines, "rules:")

	// 7a. Local preferred-IP speedtest client & cfst engine direct bypass (prevents TUN mode hijacking)
	lines = append(lines,
		fmt.Sprintf("  - %s", yamlQuote("PROCESS-NAME-REGEX,"+suohaClientProcessRegex+",DIRECT")),
		fmt.Sprintf("  - %s", yamlQuote("PROCESS-NAME-REGEX,"+cfstEngineProcessRegex+",DIRECT")),
	)

	// 7b. LAN & loopback direct
	lines = append(lines,
		"  - RULE-SET,private_domain,DIRECT",
		"  - RULE-SET,private_ip,DIRECT,no-resolve",
	)

	// 7c. Deployment server self-access protection (default DIRECT via Server-服务器运维; switchable to PROXY)
	for _, dom := range srvTargets.Domains {
		lines = append(lines, fmt.Sprintf("  - DOMAIN,%s,%s", dom, GroupServer))
	}
	for _, cidr4 := range srvTargets.IPv4CIDRs {
		lines = append(lines, fmt.Sprintf("  - IP-CIDR,%s,%s,no-resolve", cidr4, GroupServer))
	}
	for _, cidr6 := range srvTargets.IPv6CIDRs {
		lines = append(lines, fmt.Sprintf("  - IP-CIDR6,%s,%s,no-resolve", cidr6, GroupServer))
	}

	// 7d. Scene & geo rule-sets
	for _, r := range postServerRuleEntries {
		if r.NoResolve {
			lines = append(lines, fmt.Sprintf("  - RULE-SET,%s,%s,no-resolve", r.Provider, r.Target))
		} else {
			lines = append(lines, fmt.Sprintf("  - RULE-SET,%s,%s", r.Provider, r.Target))
		}
	}
	lines = append(lines,
		fmt.Sprintf("  - MATCH,%s", GroupFinal),
		"",
	)

	return strings.Join(lines, "\n")
}

func appendSelectGroup(lines *[]string, name string, proxies []string) {
	*lines = append(*lines,
		fmt.Sprintf("  - name: %s", yamlQuote(name)),
		"    type: select",
		"    proxies:",
	)
	for _, p := range proxies {
		*lines = append(*lines, fmt.Sprintf("      - %s", yamlQuote(p)))
	}
}

func appendURLTestGroup(lines *[]string, name string, groupType string, proxies []string, tolerance int) {
	*lines = append(*lines,
		fmt.Sprintf("  - name: %s", yamlQuote(name)),
		fmt.Sprintf("    type: %s", groupType),
		fmt.Sprintf("    url: %s", yamlQuote(healthCheckURL)),
		"    interval: 300",
	)
	if tolerance > 0 {
		*lines = append(*lines, fmt.Sprintf("    tolerance: %d", tolerance))
	}
	*lines = append(*lines,
		"    lazy: true",
		"    proxies:",
	)
	for _, p := range proxies {
		*lines = append(*lines, fmt.Sprintf("      - %s", yamlQuote(p)))
	}
}
