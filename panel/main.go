package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/firewall"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/server"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/subgen"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/supervisor"
)

//go:embed web/*
var embeddedWebFS embed.FS

const defaultDataDir = "/opt/suoha"

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && (!strings.HasPrefix(args[0], "-") || args[0] == "-h" || args[0] == "--help") {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "serve":
		runServe(args)
	case "init":
		runInit(args)
	case "info", "status":
		runInfo(args)
	case "reset-password", "reset-pwd":
		runResetPassword(args)
	case "set-port":
		runSetPort(args)
	case "argo-panel":
		runArgoPanelToggle(args)
	case "reality":
		runReality(args)
	case "firewall", "ufw":
		runFirewall(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`New-Suoha Web 管理面板服务端 (suoha-panel)

用法:
  suoha-panel serve [-data-dir /opt/suoha]          启动常驻 Web 面板与统一网关服务
  suoha-panel init [-data-dir /opt/suoha]           初始化配置(自动兼容迁移旧版数据)并输出初始凭据
  suoha-panel info [-data-dir /opt/suoha]           查看当前面板地址、订阅链接与客户端命令
  suoha-panel reset-password [-user X] [-password Y] 重置管理员账号与登录密码(不指定密码则随机生成)
  suoha-panel set-port [-data-dir /opt/suoha] <端口> 修改面板与订阅共用固定监听端口(自动放行防火墙)
  suoha-panel argo-panel <on|off|quick>             开启/关闭 Argo 穿透权限，或 quick 一键启动临时隧道穿透面板
  suoha-panel reality <status|on|off|sni|port|rekey|scan> [参数]
                                                    管理 VLESS+Reality+Vision 直连节点与扫描可用 SNI 域名
  suoha-panel ufw <status|sync|enable|disable|allow|deny|limit|delete|install> [参数]
                                                    管理 VPS 系统内部 UFW 防火墙与端口放行规则`)
}

func openStore(dataDir string, noLegacy bool) *config.Store {
	syncLegacy := !noLegacy && os.Geteuid() == 0
	store, err := config.LoadOrInit(dataDir, config.DefaultLegacyPaths(), syncLegacy)
	if err != nil {
		log.Fatalf("[错误] 加载配置目录 %s 失败: %v", dataDir, err)
	}
	return store
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板持久化数据目录")
	portOverride := fs.Int("port", 0, "覆盖监听端口 (可选)")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用同步写入 /etc/suoha_sub_* 与 /var/www/suoha_sub")
	_ = fs.Parse(args)

	store := openStore(*dataDir, *noLegacy)
	if *portOverride > 0 && *portOverride <= 65535 {
		_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
			d.ListenPort = *portOverride
			return nil
		})
	}
	if initPwd := store.InitialGeneratedPassword(); initPwd != "" {
		cfg := store.GetConfig()
		log.Printf("[初始化] 首次启动已生成管理员账号: %s | 初始密码: %s", cfg.AdminUser, initPwd)
	}

	ringLogs := supervisor.NewRingLog(350)
	var handlerRef *server.Handler

	mgr := supervisor.NewManager(store, ringLogs, func() {
		if handlerRef != nil {
			handlerRef.SyncStaticSubscriptions()
		}
	})

	// Dynamic listener manager supporting live port changes from Web UI
	var srvMu sync.Mutex
	var activeSrv *http.Server

	startListenerOnPort := func(port int) (*http.Server, net.Listener, error) {
		ln, err := listenDualStack(port)
		if err != nil {
			return nil, nil, err
		}
		s := &http.Server{
			Handler:           handlerRef,
			ReadHeaderTimeout: 15 * time.Second,
		}
		return s, ln, nil
	}

	switchPort := func(newPort int) error {
		srvMu.Lock()
		defer srvMu.Unlock()

		newSrv, newLn, err := startListenerOnPort(newPort)
		if err != nil {
			return err
		}
		oldSrv := activeSrv
		activeSrv = newSrv

		go func() {
			ringLogs.Add("panel", fmt.Sprintf("HTTP 统一网关监听端口已热切换至 :%d", newPort))
			if err := newSrv.Serve(newLn); err != nil && err != http.ErrServerClosed {
				log.Printf("[警告] HTTP 服务异常退出: %v", err)
			}
		}()

		if oldSrv != nil {
			go func(s *http.Server) {
				time.Sleep(500 * time.Millisecond)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = s.Shutdown(ctx)
			}(oldSrv)
		}
		return nil
	}

	h, err := server.NewHandler(store, mgr, embeddedWebFS, switchPort)
	if err != nil {
		log.Fatalf("[错误] 初始化 Web 处理器失败: %v", err)
	}
	handlerRef = h

	listenPort := store.GetConfig().ListenPort
	srvMu.Lock()
	srv, ln, err := startListenerOnPort(listenPort)
	if err != nil {
		srvMu.Unlock()
		log.Fatalf("[错误] 无法监听端口 :%d (%v)", listenPort, err)
	}
	activeSrv = srv
	srvMu.Unlock()

	ringLogs.Add("panel", fmt.Sprintf("New-Suoha Web 面板已启动，监听端口 :%d", listenPort))
	log.Printf("[启动] New-Suoha Web 管理面板正在监听 :%d (数据目录: %s)", listenPort, store.DataDir())

	go mgr.InitNetworkAndAutostart()
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[错误] HTTP 服务退出: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("[停止] 收到信号 %v，正在关闭隧道与面板服务...", sig)

	mgr.Shutdown()
	srvMu.Lock()
	curSrv := activeSrv
	srvMu.Unlock()
	if curSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = curSrv.Shutdown(ctx)
	}
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	user := fs.String("user", "", "指定管理员账号 (可选)")
	pass := fs.String("password", "", "指定管理员密码 (可选)")
	port := fs.Int("port", 0, "指定监听端口 (可选)")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	store := openStore(*dataDir, *noLegacy)
	shownPassword := store.InitialGeneratedPassword()

	if *user != "" || *pass != "" || (*port > 0 && *port <= 65535) {
		_, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			if strings.TrimSpace(*user) != "" {
				d.AdminUser = strings.TrimSpace(*user)
			}
			if strings.TrimSpace(*pass) != "" {
				h, err := config.HashPassword(*pass)
				if err != nil {
					return err
				}
				d.AdminPassHash = h
				shownPassword = *pass
			}
			if *port > 0 && *port <= 65535 {
				d.ListenPort = *port
			}
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 更新初始化参数失败: %v", err)
		}
	}

	_ = firewall.SyncPanelPorts(context.Background(), store.GetConfig(), false)
	printPanelSummary(store, shownPassword)
}

func runInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	store := openStore(*dataDir, *noLegacy)
	printPanelSummary(store, store.InitialGeneratedPassword())
}

func runResetPassword(args []string) {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	user := fs.String("user", "", "新的管理员用户名 (留空保持原用户名)")
	pass := fs.String("password", "", "新的登录密码 (留空随机生成 12 位密码)")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	store := openStore(*dataDir, *noLegacy)
	newPass := strings.TrimSpace(*pass)
	if newPass == "" {
		newPass = config.RandomPassword(12)
	}
	hash, err := config.HashPassword(newPass)
	if err != nil {
		log.Fatalf("[错误] 生成密码哈希失败: %v", err)
	}

	cfg, err := store.UpdateConfig(func(d *config.PanelConfig) error {
		if u := strings.TrimSpace(*user); u != "" {
			d.AdminUser = u
		}
		d.AdminPassHash = hash
		return nil
	})
	if err != nil {
		log.Fatalf("[错误] 保存新凭据失败: %v", err)
	}

	fmt.Println("==========================================================")
	fmt.Println("          管理员登录凭据已重置 (请重启面板服务生效)       ")
	fmt.Println("==========================================================")
	fmt.Printf("管理员账号 : %s\n", cfg.AdminUser)
	fmt.Printf("新登录密码 : %s\n", newPass)
	fmt.Println("==========================================================")
}

func runSetPort(args []string) {
	fs := flag.NewFlagSet("set-port", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 {
		log.Fatalf("用法: suoha-panel set-port <1-65535>")
	}
	p, err := strconv.Atoi(rest[0])
	if err != nil || p < 1 || p > 65535 {
		log.Fatalf("[错误] 端口号无效: %s (范围 1-65535)", rest[0])
	}

	store := openStore(*dataDir, *noLegacy)
	updatedCfg, err := store.UpdateConfig(func(d *config.PanelConfig) error {
		d.ListenPort = p
		return nil
	})
	if err != nil {
		log.Fatalf("[错误] 保存端口失败: %v", err)
	}
	if synced := firewall.SyncPanelPorts(context.Background(), updatedCfg, false); len(synced) > 0 {
		fmt.Printf("系统防火墙已自动同步放行端口: %s\n", strings.Join(synced, ", "))
	}
	fmt.Printf("监听端口已更新为 %d (重启 suoha-panel 服务后生效)\n", p)
}

func runArgoPanelToggle(args []string) {
	fs := flag.NewFlagSet("argo-panel", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	rest := fs.Args()
	action := ""
	if len(rest) > 0 {
		action = strings.ToLower(strings.TrimSpace(rest[0]))
	}
	store := openStore(*dataDir, *noLegacy)

	switch action {
	case "on", "off":
		enable := action == "on"
		cfg, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.AllowArgoPanel = enable
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 更新配置失败: %v", err)
		}
		if enable {
			fmt.Println("已开启通过 Argo 隧道域名访问管理面板。")
			if !cfg.Tunnel.Enabled && !cfg.Tunnel.PanelQuickTunnel {
				fmt.Println("提示: 当前尚未启用 Argo 隧道进程，如需立即生成临时穿透地址可执行: suoha argo quick")
			}
		} else {
			fmt.Println("已关闭通过 Argo 隧道域名访问管理面板")
		}

	case "quick":
		_, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.AllowArgoPanel = true
			if !d.Tunnel.Enabled {
				d.Tunnel.PanelQuickTunnel = true
			} else if d.Tunnel.Mode == "quick" && d.Tunnel.QuickTopology == "dual" {
				d.Tunnel.PanelQuickTunnel = true
			}
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 开启 Argo 面板穿透隧道失败: %v", err)
		}
		fmt.Println("已开启 Argo 面板穿透并启用临时隧道 (Quick Tunnel)，正在等待服务分配 https:// 穿透域名...")

	case "wait":
		deadline := time.Now().Add(18 * time.Second)
		for time.Now().Before(deadline) {
			if snap, ok := supervisor.ReadRuntimeSnapshot(store.DataDir()); ok && strings.TrimSpace(snap.ArgoPanel) != "" {
				break
			}
			time.Sleep(600 * time.Millisecond)
		}
		printPanelSummary(store, store.InitialGeneratedPassword())

	default:
		log.Fatalf("用法: suoha-panel argo-panel <on|off|quick>")
	}
}

func runReality(args []string) {
	fs := flag.NewFlagSet("reality", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	rest := fs.Args()
	action := "status"
	if len(rest) > 0 {
		action = strings.ToLower(strings.TrimSpace(rest[0]))
	}

	store := openStore(*dataDir, *noLegacy)

	switch action {
	case "status", "info":
		printRealitySummary(store)

	case "on", "enable":
		cur := store.GetConfig()
		newPort := cur.Protocols.RealityPort
		newSNI := cur.Protocols.RealitySNI
		for _, tok := range rest[1:] {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if p, err := strconv.Atoi(tok); err == nil && p >= 1 && p <= 65535 {
				newPort = p
			} else if d := config.ExtractRealityDomain(tok); config.IsValidRealityDomain(d) {
				newSNI = d
			} else {
				log.Fatalf("[错误] 无法识别的参数 %q (可指定端口号或有效 SNI 域名)", tok)
			}
		}
		if newPort == cur.ListenPort {
			log.Fatalf("[错误] Reality 端口 (%d) 不能与面板监听端口相同", newPort)
		}
		updatedCfg, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.Protocols.RealityEnabled = true
			d.Protocols.RealityPort = newPort
			d.Protocols.RealitySNI = newSNI
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 开启 Reality 失败: %v", err)
		}
		if synced := firewall.SyncPanelPorts(context.Background(), updatedCfg, false); len(synced) > 0 {
			fmt.Printf("系统防火墙已自动同步放行端口: %s\n", strings.Join(synced, ", "))
		}
		fmt.Printf("已开启 VLESS + Reality + XTLS-RPRX-Vision 直连节点 (端口 :%d | SNI: %s)\n", newPort, newSNI)
		printRealitySummary(store)

	case "off", "disable":
		_, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.Protocols.RealityEnabled = false
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 关闭 Reality 失败: %v", err)
		}
		fmt.Println("已关闭 VLESS + Reality + XTLS-RPRX-Vision 直连节点 (重启 suoha-panel 服务后生效)")

	case "sni", "set-sni", "domain":
		if len(rest) < 2 {
			log.Fatalf("用法: suoha-panel reality sni <域名>  (默认 Apple 域名: %s)", config.DefaultRealitySNI)
		}
		domain := config.ExtractRealityDomain(rest[1])
		if !config.IsValidRealityDomain(domain) {
			log.Fatalf("[错误] 无效的 SNI 域名: %s (示例: www.apple.com)", rest[1])
		}
		_, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.Protocols.RealitySNI = domain
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 保存 Reality SNI 域名失败: %v", err)
		}
		fmt.Printf("已将 Reality 伪装 SNI 域名设置为: %s (重启 suoha-panel 服务后生效)\n", domain)

	case "port", "set-port":
		if len(rest) < 2 {
			log.Fatalf("用法: suoha-panel reality port <1-65535>")
		}
		p, err := strconv.Atoi(strings.TrimSpace(rest[1]))
		if err != nil || p < 1 || p > 65535 {
			log.Fatalf("[错误] 端口号无效: %s (范围 1-65535)", rest[1])
		}
		cur := store.GetConfig()
		if p == cur.ListenPort {
			log.Fatalf("[错误] Reality 监听端口 (%d) 不能与面板监听端口相同", p)
		}
		updatedCfg, err := store.UpdateConfig(func(d *config.PanelConfig) error {
			d.Protocols.RealityPort = p
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 保存 Reality 端口失败: %v", err)
		}
		if synced := firewall.SyncPanelPorts(context.Background(), updatedCfg, false); len(synced) > 0 {
			fmt.Printf("系统防火墙已自动同步放行端口: %s\n", strings.Join(synced, ", "))
		}
		fmt.Printf("已将 Reality 监听端口更新为 %d (重启 suoha-panel 服务后生效)\n", p)

	case "rekey", "rotate":
		priv, pub, err := config.GenerateRealityKeyPair()
		if err != nil {
			log.Fatalf("[错误] 生成 Reality 密钥对失败: %v", err)
		}
		sid := config.RandomHex(4)
		_, err = store.UpdateConfig(func(d *config.PanelConfig) error {
			d.Protocols.RealityPrivateKey = priv
			d.Protocols.RealityPublicKey = pub
			d.Protocols.RealityShortID = sid
			return nil
		})
		if err != nil {
			log.Fatalf("[错误] 保存新密钥对失败: %v", err)
		}
		fmt.Printf("已重新生成 Reality X25519 密钥对与 ShortID (PublicKey: %s | ShortID: %s)\n", pub, sid)

	case "scan", "check":
		mode := "preset"
		var customDomains []string
		for _, tok := range rest[1:] {
			low := strings.ToLower(strings.TrimSpace(tok))
			switch low {
			case "", "preset", "-preset", "--preset":
				mode = "preset"
			case "neighbor", "-neighbor", "--neighbor", "subnet", "/24":
				mode = "neighbor"
			default:
				parsed := supervisor.ParseCustomDomainInputs(tok)
				if len(parsed) > 0 {
					mode = "custom"
					customDomains = append(customDomains, parsed...)
				}
			}
		}

		netInfo := supervisor.DetectNetwork()
		fmt.Printf("正在从本机扫描检测支持 TLS 1.3 + HTTP/2 (h2) 的 Reality 可用域名 (模式: %s)...\n", mode)
		ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
		defer cancel()

		report := supervisor.ScanRealityDomains(ctx, supervisor.RealityScanOptions{
			Mode:          mode,
			CustomDomains: customDomains,
			ServerIP:      netInfo.ServerIP,
			Port:          443,
		})

		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("%-34s %-12s %-8s %s\n", "候选域名 (SNI)", "兼容性", "延迟", "解析 IP / 证书信息")
		fmt.Println("--------------------------------------------------------------------------------")
		for _, r := range report.Results {
			status := "不兼容"
			detail := r.Reason
			if r.Valid {
				status = "TLS1.3+H2"
				detail = r.IP
				if r.Issuer != "" {
					detail += " (" + r.Issuer + ")"
				}
			}
			lat := "-"
			if r.LatencyMs > 0 {
				lat = fmt.Sprintf("%dms", r.LatencyMs)
			}
			fmt.Printf("%-34s %-12s %-8s %s\n", r.Domain, status, lat, detail)
		}
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("扫描完成: 共检测 %d 个域名，可用 %d 个。", report.Scanned, report.ValidCount)
		if report.Note != "" {
			fmt.Printf(" (%s)", report.Note)
		}
		fmt.Println("\n提示: 可执行 `suoha reality sni <域名>` 切换伪装域名，或 `suoha reality on` 启用直连节点。")

	default:
		log.Fatalf("用法: suoha-panel reality <status|on|off|sni <域名>|port <端口>|rekey|scan [preset|neighbor|域名]>")
	}
}

func runFirewall(args []string) {
	fs := flag.NewFlagSet("ufw", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	rest := fs.Args()
	action := "status"
	if len(rest) > 0 {
		action = strings.ToLower(strings.TrimSpace(rest[0]))
	}

	store := openStore(*dataDir, *noLegacy)
	cfg := store.GetConfig()
	ctx := context.Background()

	switch action {
	case "status", "info", "list":
		printFirewallSummary(ctx, cfg)

	case "install":
		fmt.Println("正在检测并安装系统 UFW 防火墙组件...")
		if err := firewall.InstallUFW(ctx); err != nil {
			log.Fatalf("[错误] %v", err)
		}
		fmt.Println("UFW 防火墙组件已安装就绪。")
		printFirewallSummary(ctx, cfg)

	case "sync":
		synced := firewall.SyncPanelPorts(ctx, cfg, true)
		if len(synced) == 0 {
			fmt.Println("提示: 当前未以 root 运行或无端口需要同步。")
		} else {
			fmt.Printf("已一键同步放行系统防火墙端口: %s\n", strings.Join(synced, ", "))
		}
		printFirewallSummary(ctx, cfg)

	case "enable", "on":
		synced, err := firewall.EnableUFW(ctx, cfg)
		if err != nil {
			log.Fatalf("[错误] %v", err)
		}
		fmt.Printf("UFW 防火墙已安全启用 (已自动预放行保护端口: %s)\n", strings.Join(synced, ", "))
		printFirewallSummary(ctx, cfg)

	case "disable", "off":
		if err := firewall.DisableUFW(ctx); err != nil {
			log.Fatalf("[错误] %v", err)
		}
		fmt.Println("UFW 防火墙已停用（规则配置仍保留）。")
		printFirewallSummary(ctx, cfg)

	case "reload":
		if err := firewall.ReloadUFW(ctx); err != nil {
			log.Fatalf("[错误] %v", err)
		}
		fmt.Println("UFW 防火墙规则已重载。")

	case "allow", "deny", "reject", "limit":
		if len(rest) < 2 {
			log.Fatalf("用法: suoha-panel ufw %s <端口或端口段[/tcp|/udp]> [备注]", action)
		}
		cmt := ""
		if len(rest) >= 3 {
			cmt = strings.Join(rest[2:], " ")
		}
		spec := firewall.RuleSpec{
			Action:  action,
			Port:    rest[1],
			Proto:   "any",
			Comment: cmt,
		}
		if err := firewall.AddRule(ctx, spec); err != nil {
			log.Fatalf("[错误] %v", err)
		}
		fmt.Printf("已添加 UFW 规则: %s %s\n", strings.ToUpper(action), rest[1])
		printFirewallSummary(ctx, cfg)

	case "delete", "del", "rm":
		if len(rest) < 2 {
			log.Fatalf("用法: suoha-panel ufw delete <规则编号> [--force]")
		}
		idx, err := strconv.Atoi(strings.TrimSpace(rest[1]))
		if err != nil || idx < 1 {
			log.Fatalf("[错误] 规则编号无效: %s", rest[1])
		}
		force := false
		for _, tok := range rest[2:] {
			if tok == "--force" || tok == "-f" {
				force = true
			}
		}
		if err := firewall.DeleteRule(ctx, idx, cfg, force); err != nil {
			log.Fatalf("[错误] %v (如需强制删除受保护规则可附加 --force)", err)
		}
		fmt.Printf("已删除 UFW 规则编号 [%d]\n", idx)
		printFirewallSummary(ctx, cfg)

	default:
		log.Fatalf("用法: suoha-panel ufw <status|sync|enable|disable|reload|allow <端口>|deny <端口>|limit <端口>|delete <编号>|install>")
	}
}

func printFirewallSummary(ctx context.Context, cfg config.PanelConfig) {
	st := firewall.GetStatus(ctx, cfg)
	stateText := "未安装 UFW (可执行 `suoha ufw install` 安装)"
	if st.UFWInstalled {
		if !st.IsRoot {
			stateText = "已安装 (需 root 权限读取实时规则)"
		} else if st.UFWActive {
			stateText = fmt.Sprintf("运行中 (active) | 入站默认: %s | 出站默认: %s",
				strings.ToUpper(st.DefaultIncoming), strings.ToUpper(st.DefaultOutgoing))
		} else {
			stateText = "已安装但未启用 (inactive)"
		}
	}

	sshStrs := make([]string, 0, len(st.DetectedSSHPorts))
	for _, p := range st.DetectedSSHPorts {
		sshStrs = append(sshStrs, fmt.Sprintf("%d/tcp", p))
	}

	fmt.Println("==========================================================================")
	fmt.Println("                     VPS 系统内部防火墙 (UFW) 状态                        ")
	fmt.Println("==========================================================================")
	fmt.Printf("UFW 状态       : %s\n", stateText)
	fmt.Printf("防失联保护端口 : SSH [%s] | 面板 [%d/tcp]", strings.Join(sshStrs, ", "), st.PanelPort)
	if st.RealityEnabled {
		fmt.Printf(" | Reality [%d/tcp]", st.RealityPort)
	}
	if st.SSEnabled {
		fmt.Printf(" | IPv6-SS [%d/tcp+udp]", st.SSPort)
	}
	fmt.Println()
	if st.OtherBackend != "" {
		fmt.Printf("底层防火墙提示 : %s\n", st.OtherBackend)
	}
	if len(st.Rules) > 0 {
		fmt.Println("--------------------------------------------------------------------------")
		fmt.Printf("%-6s %-22s %-12s %-18s %s\n", "编号", "目标端口/协议", "动作", "来源地址", "角色/备注")
		fmt.Println("--------------------------------------------------------------------------")
		for _, r := range st.Rules {
			idxLabel := "-"
			if r.Index > 0 {
				idxLabel = fmt.Sprintf("[%d]", r.Index)
			}
			toLabel := r.To
			if r.IPv6 {
				toLabel += " (v6)"
			}
			noteParts := []string{}
			if r.Role != "" {
				noteParts = append(noteParts, "["+r.Role+"]")
			}
			if r.Comment != "" {
				noteParts = append(noteParts, r.Comment)
			}
			fmt.Printf("%-6s %-22s %-12s %-18s %s\n", idxLabel, toLabel, r.Action, r.From, strings.Join(noteParts, " "))
		}
	} else if st.UFWInstalled && st.IsRoot {
		fmt.Println("--------------------------------------------------------------------------")
		fmt.Println("暂无已配置的 UFW 端口规则（可执行 `suoha ufw sync` 一键同步放行节点端口）")
	}
	fmt.Println("==========================================================================")
}

func printRealitySummary(store *config.Store) {
	cfg := store.GetConfig()
	proto := cfg.Protocols
	netInfo := supervisor.DetectNetwork()
	srvHost := netInfo.ServerIP
	if srvHost == "" {
		srvHost = netInfo.IPv6Addr
	}
	subOut := subgen.Generate(cfg, store.GetPreferred(), subgen.RuntimeState{
		ServerIP: srvHost,
	})

	stText := "未启用 (可执行 `suoha reality on` 开启)"
	if proto.RealityEnabled {
		stText = "已启用 (XTLS-RPRX-Vision 直连)"
	}

	fmt.Println("==========================================================")
	fmt.Println("        VLESS + Reality + XTLS-RPRX-Vision 节点信息       ")
	fmt.Println("==========================================================")
	fmt.Printf("启用状态       : %s\n", stText)
	fmt.Printf("公网监听端口   : %d (TCP)\n", proto.RealityPort)
	fmt.Printf("伪装 SNI 域名  : %s\n", proto.RealitySNI)
	fmt.Printf("uTLS 客户端指纹: %s\n", proto.RealityFingerprint)
	fmt.Printf("Public Key(pbk): %s\n", proto.RealityPublicKey)
	fmt.Printf("Short ID (sid) : %s\n", proto.RealityShortID)
	for _, n := range subOut.Nodes {
		if n.Protocol == "reality" {
			fmt.Println("----------------------------------------------------------")
			fmt.Printf("直连节点链接   : %s\n", n.URI)
			break
		}
	}
	fmt.Println("==========================================================")
}

func printPanelSummary(store *config.Store, plainPwd string) {
	cfg := store.GetConfig()
	snap, snapAlive := supervisor.ReadRuntimeSnapshot(store.DataDir())

	host := strings.TrimSpace(cfg.Protocols.ServerHostOverride)
	if host == "" && snapAlive && strings.TrimSpace(snap.ServerIP) != "" {
		host = strings.TrimSpace(snap.ServerIP)
	}
	if host == "" {
		netInfo := supervisor.DetectNetwork()
		host = netInfo.ServerIP
	}
	if host == "" {
		host = "<VPS公网IP>"
	}
	baseURL := fmt.Sprintf("http://%s:%d", subgen.FormatHostForURL(host), cfg.ListenPort)

	argoDomain := ""
	if snapAlive && strings.TrimSpace(snap.ArgoPanel) != "" {
		argoDomain = strings.TrimSpace(snap.ArgoPanel)
	} else if cfg.Tunnel.Enabled && cfg.Tunnel.Mode == "token" && strings.TrimSpace(cfg.Tunnel.CustomDomain) != "" {
		argoDomain = strings.TrimSpace(cfg.Tunnel.CustomDomain)
	}

	argoLabel := "Argo 面板穿透  "
	argoValue := ""
	switch {
	case argoDomain != "" && cfg.AllowArgoPanel:
		argoLabel = "Argo 面板地址  "
		argoValue = fmt.Sprintf("https://%s/  (免端口 HTTPS 穿透访问)", argoDomain)
	case argoDomain != "" && !cfg.AllowArgoPanel:
		argoValue = fmt.Sprintf("已关闭后台穿透 (隧道域名 https://%s 仅开放订阅)", argoDomain)
	case !cfg.AllowArgoPanel:
		argoValue = "已关闭 (仅开放直连 IP:Port 访问后台)"
	case cfg.Tunnel.Enabled && cfg.Tunnel.Mode == "quick" && cfg.Tunnel.QuickTopology == "dual" && !cfg.Tunnel.PanelQuickTunnel:
		argoValue = "双隧道模式未勾选独立面板隧道 (可执行 suoha argo quick 一键开启面板穿透)"
	case snapAlive && snap.TunnelState == "starting":
		argoLabel = "Argo 面板地址  "
		argoValue = "正在向 Cloudflare 申请临时隧道域名，请稍候数秒再执行 suoha info 查看..."
	default:
		argoValue = "尚未启动 Argo 隧道 (可在面板【隧道管理】开启，或执行 suoha argo quick 一键分配 https:// 地址)"
	}

	realityHint := fmt.Sprintf("未启用 (默认 Apple SNI: %s，可在面板开启或执行 suoha reality on)", cfg.Protocols.RealitySNI)
	if cfg.Protocols.RealityEnabled {
		realityHint = fmt.Sprintf("已启用 (端口 :%d | SNI: %s | XTLS-RPRX-Vision)", cfg.Protocols.RealityPort, cfg.Protocols.RealitySNI)
	}

	clientServerURL := baseURL
	if argoDomain != "" {
		clientServerURL = "https://" + argoDomain
	}

	fmt.Println("==========================================================")
	fmt.Println("             New-Suoha Web 管理面板信息                   ")
	fmt.Println("==========================================================")
	fmt.Printf("面板直连地址   : %s/\n", baseURL)
	fmt.Printf("%s: %s\n", argoLabel, argoValue)
	fmt.Printf("管理员用户名   : %s\n", cfg.AdminUser)
	if plainPwd != "" {
		fmt.Printf("初始登录密码   : %s  (请妥善保存并登录后按需修改)\n", plainPwd)
	} else {
		fmt.Printf("管理员登录密码 : (已加密保存，遗忘可执行 suoha 重置密码)\n")
	}
	fmt.Printf("Reality 直连   : %s\n", realityHint)
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("通用订阅直链   : %s/%s/sub.txt\n", baseURL, cfg.SubUUID)
	fmt.Printf("Clash 配置直链 : %s/%s/clash.yaml\n", baseURL, cfg.SubUUID)
	if argoDomain != "" {
		fmt.Printf("Argo 通用订阅  : https://%s/%s/sub.txt\n", argoDomain, cfg.SubUUID)
		fmt.Printf("Argo Clash配置 : https://%s/%s/clash.yaml\n", argoDomain, cfg.SubUUID)
	}
	fmt.Printf("客户端 Token   : %s\n", cfg.ClientToken)
	fmt.Printf("一键优选测速   : sh -c \"$(curl -fsSL '%s/api/client.sh?token=%s&once=1')\"\n", clientServerURL, cfg.ClientToken)
	fmt.Println("==========================================================")
}

func listenDualStack(port int) (net.Listener, error) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	return net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
}
