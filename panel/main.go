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
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
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
  suoha-panel set-port [-data-dir /opt/suoha] <端口> 修改面板与订阅共用固定监听端口
  suoha-panel argo-panel <on|off>                   开启或关闭通过 Argo 隧道域名访问管理面板`)
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
	_, err = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.ListenPort = p
		return nil
	})
	if err != nil {
		log.Fatalf("[错误] 保存端口失败: %v", err)
	}
	fmt.Printf("监听端口已更新为 %d (重启 suoha-panel 服务后生效)\n", p)
}

func runArgoPanelToggle(args []string) {
	fs := flag.NewFlagSet("argo-panel", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "面板数据目录")
	noLegacy := fs.Bool("no-legacy-sync", false, "禁用旧版文件同步")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 1 || (rest[0] != "on" && rest[0] != "off") {
		log.Fatalf("用法: suoha-panel argo-panel <on|off>")
	}
	enable := rest[0] == "on"
	store := openStore(*dataDir, *noLegacy)
	_, err := store.UpdateConfig(func(d *config.PanelConfig) error {
		d.AllowArgoPanel = enable
		return nil
	})
	if err != nil {
		log.Fatalf("[错误] 更新配置失败: %v", err)
	}
	if enable {
		fmt.Println("已开启通过 Argo 隧道域名访问管理面板 (重启面板服务或面板热加载后生效)")
	} else {
		fmt.Println("已关闭通过 Argo 隧道域名访问管理面板")
	}
}

func printPanelSummary(store *config.Store, plainPwd string) {
	cfg := store.GetConfig()
	netInfo := supervisor.DetectNetwork()
	host := strings.TrimSpace(cfg.Protocols.ServerHostOverride)
	if host == "" {
		host = netInfo.ServerIP
	}
	if host == "" {
		host = "<VPS公网IP>"
	}
	baseURL := fmt.Sprintf("http://%s:%d", subgen.FormatHostForURL(host), cfg.ListenPort)

	argoHint := "已允许 (启动单隧道梭哈或固定隧道后可通过 HTTPS 隧道域名免端口访问)"
	if !cfg.AllowArgoPanel {
		argoHint = "已关闭 (仅开放直连 IP:Port 访问后台)"
	}

	fmt.Println("==========================================================")
	fmt.Println("             New-Suoha Web 管理面板信息                   ")
	fmt.Println("==========================================================")
	fmt.Printf("面板访问地址   : %s/\n", baseURL)
	fmt.Printf("管理员用户名   : %s\n", cfg.AdminUser)
	if plainPwd != "" {
		fmt.Printf("初始登录密码   : %s  (请妥善保存并登录后按需修改)\n", plainPwd)
	} else {
		fmt.Printf("管理员登录密码 : (已加密保存，遗忘可执行 suoha 重置密码)\n")
	}
	fmt.Printf("Argo 面板穿透  : %s\n", argoHint)
	fmt.Println("----------------------------------------------------------")
	fmt.Printf("通用订阅直链   : %s/%s/sub.txt\n", baseURL, cfg.SubUUID)
	fmt.Printf("Clash 配置直链 : %s/%s/clash.yaml\n", baseURL, cfg.SubUUID)
	fmt.Printf("客户端 Token   : %s\n", cfg.ClientToken)
	fmt.Printf("一键优选测速   : sh -c \"$(curl -fsSL '%s/api/client.sh?token=%s&once=1')\"\n", baseURL, cfg.ClientToken)
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
