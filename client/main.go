package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Config holds the runtime configuration for suoha-client.
type Config struct {
	Server   string  `json:"server"`
	Token    string  `json:"token"`
	Interval string  `json:"interval"`
	Once     bool    `json:"once"`
	Top      int     `json:"top"`
	Port     int     `json:"port"`
	DisableD bool    `json:"dd"`
	IPv6     bool    `json:"ipv6"`
	SpeedURL string  `json:"url"`
	MaxLat   int     `json:"tl"`
	MinSpeed float64 `json:"sl"`
	CfstDir  string  `json:"cfst_dir"`
	CfstBin  string  `json:"cfst_bin"`
	CfstArgs string  `json:"cfst_args"`
}

// PreferredIP represents a single optimized Cloudflare IP entry uploaded to the server.
type PreferredIP struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Latency string `json:"latency"`
	Speed   string `json:"speed"`
	Colo    string `json:"colo,omitempty"`
	Label   string `json:"label"`
}

// UploadPayload is the JSON body sent to POST /api/update_ips.
type UploadPayload struct {
	IPs []PreferredIP `json:"ips"`
}

// UploadResponse is the JSON response from POST /api/update_ips.
type UploadResponse struct {
	OK          bool   `json:"ok"`
	Count       int    `json:"count"`
	UpdatedAt   string `json:"updated_at"`
	Regenerated bool   `json:"regenerated"`
	Error       string `json:"error,omitempty"`
}

var defaultIPv4CIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var defaultIPv6CIDRs = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func main() {
	cfg := Config{
		Server:   os.Getenv("SUOHA_SERVER"),
		Token:    os.Getenv("SUOHA_TOKEN"),
		Interval: "6h",
		Once:     false,
		Top:      5,
		Port:     443,
		DisableD: false,
		IPv6:     false,
		MaxLat:   300,
		MinSpeed: 0,
		CfstDir:  "./cfst",
	}

	var configPath string
	flag.StringVar(&configPath, "config", "", "JSON 配置文件路径 (默认若当前目录存在 config.json 则自动加载)")
	flag.StringVar(&cfg.Server, "server", cfg.Server, "服务端订阅地址, 例如 http://1.2.3.4:28000 (或设置环境变量 SUOHA_SERVER)")
	flag.StringVar(&cfg.Token, "token", cfg.Token, "服务端鉴权 Token (或设置环境变量 SUOHA_TOKEN)")
	flag.StringVar(&cfg.Interval, "interval", cfg.Interval, "后台定时测速间隔 (如 6h, 2h, 30m)")
	flag.BoolVar(&cfg.Once, "once", cfg.Once, "单次运行模式: 测速并上传一次后立即退出")
	flag.IntVar(&cfg.Top, "top", cfg.Top, "每次上传的最优 IP 数量 (默认 5)")
	flag.IntVar(&cfg.Port, "port", cfg.Port, "Cloudflare 节点 TLS 端口 (默认 443, 可选 2053/2083/2087/2096/8443)")
	flag.BoolVar(&cfg.DisableD, "dd", cfg.DisableD, "禁用下载测速, 仅按延迟筛选优选 IP")
	flag.BoolVar(&cfg.IPv6, "ipv6", cfg.IPv6, "使用 IPv6 数据段 (ipv6.txt) 进行优选测速")
	flag.StringVar(&cfg.SpeedURL, "url", cfg.SpeedURL, "自定义 CloudflareSpeedTest 下载测速地址 (-url)")
	flag.IntVar(&cfg.MaxLat, "tl", cfg.MaxLat, "平均延迟上限 ms (默认 300)")
	flag.Float64Var(&cfg.MinSpeed, "sl", cfg.MinSpeed, "下载速度下限 MB/s (默认 0 不限制)")
	flag.StringVar(&cfg.CfstDir, "cfst-dir", cfg.CfstDir, "CloudflareSpeedTest 存放目录 (不存在时自动下载)")
	flag.StringVar(&cfg.CfstBin, "cfst-bin", cfg.CfstBin, "指定已有的 CloudflareSpeedTest 可执行文件路径")
	flag.StringVar(&cfg.CfstArgs, "cfst-args", cfg.CfstArgs, "附加透传给 CloudflareSpeedTest 的自定义参数")
	flag.Parse()

	// Load config file if specified or if ./config.json exists
	if configPath == "" {
		if _, err := os.Stat("config.json"); err == nil {
			configPath = "config.json"
		}
	}
	if configPath != "" {
		if err := loadConfigFile(configPath, &cfg); err != nil {
			log.Fatalf("[错误] 读取配置文件 %s 失败: %v", configPath, err)
		}
		// Re-parse CLI flags so explicit CLI flags override config file values
		flag.Parse()
	}

	cfg.Server = strings.TrimSpace(cfg.Server)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Server == "" || cfg.Token == "" {
		fmt.Fprintf(os.Stderr, "用法示例:\n")
		fmt.Fprintf(os.Stderr, "  常驻后台定时更新: %s -server \"http://<VPS_IP>:<端口>\" -token \"<Token>\"\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "  单次立即测速更新: %s -server \"http://<VPS_IP>:<端口>\" -token \"<Token>\" -once\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}

	if cfg.Top <= 0 {
		cfg.Top = 5
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		cfg.Port = 443
	}

	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil || interval < time.Minute {
		log.Printf("[提示] 无效或过短的定时间隔 %q, 默认使用 6h", cfg.Interval)
		interval = 6 * time.Hour
	}

	apiURL := normalizeAPIURL(cfg.Server)
	log.Printf("[启动] New-Suoha 客户端优选 IP 助手 (%s/%s)", runtime.GOOS, runtime.GOARCH)
	log.Printf("[配置] 服务端接口: %s | 每次精选 Top %d | 端口: %d | 仅延迟(-dd): %v", apiURL, cfg.Top, cfg.Port, cfg.DisableD)

	runTask := func() {
		if err := executeSpeedTestAndUpload(&cfg, apiURL); err != nil {
			log.Printf("[失败] 本轮优选测速或上传出错: %v", err)
		}
	}

	runTask()
	if cfg.Once {
		log.Printf("[完成] 单次运行模式 (-once) 已执行完毕，程序退出。")
		return
	}

	log.Printf("[守护] 已进入后台定时模式，每 %v 自动执行一次优选测速与订阅更新 (按 Ctrl+C 退出)...", interval)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("[定时] 触发新一轮本地优选 IP 测速...")
			runTask()
		case sig := <-sigCh:
			log.Printf("[退出] 收到信号 %v，正在停止后台进程...", sig)
			return
		}
	}
}

func loadConfigFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}

func normalizeAPIURL(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "http://" + s
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, "/sub.txt")
	s = strings.TrimSuffix(s, "/clash.yaml")
	if !strings.HasSuffix(s, "/api/update_ips") {
		s = s + "/api/update_ips"
	}
	return s
}

func executeSpeedTestAndUpload(cfg *Config, apiURL string) error {
	absDir, err := filepath.Abs(cfg.CfstDir)
	if err != nil {
		return fmt.Errorf("解析工作目录失败: %w", err)
	}
	if err := os.MkdirAll(absDir, 0755); err != nil {
		return fmt.Errorf("创建目录 %s 失败: %w", absDir, err)
	}

	binPath, err := ensureCfstBinary(cfg, absDir)
	if err != nil {
		return fmt.Errorf("准备 CloudflareSpeedTest 失败: %w", err)
	}

	ipFileName := "ip.txt"
	if cfg.IPv6 {
		ipFileName = "ipv6.txt"
	}
	ipFilePath := filepath.Join(absDir, ipFileName)
	if err := ensureIPRangeFile(ipFilePath, cfg.IPv6); err != nil {
		return fmt.Errorf("准备 IP 段文件 %s 失败: %w", ipFilePath, err)
	}

	resultCSV := filepath.Join(absDir, "result.csv")
	_ = os.Remove(resultCSV)

	args := []string{
		"-f", ipFilePath,
		"-o", resultCSV,
		"-tp", strconv.Itoa(cfg.Port),
		"-dn", strconv.Itoa(cfg.Top),
		"-p", "0",
	}
	if cfg.MaxLat > 0 {
		args = append(args, "-tl", strconv.Itoa(cfg.MaxLat))
	}
	if cfg.DisableD {
		args = append(args, "-dd")
	} else if cfg.MinSpeed > 0 {
		args = append(args, "-sl", fmt.Sprintf("%.2f", cfg.MinSpeed))
	}
	if cfg.SpeedURL != "" {
		args = append(args, "-url", cfg.SpeedURL)
	}
	if strings.TrimSpace(cfg.CfstArgs) != "" {
		extra := strings.Fields(cfg.CfstArgs)
		args = append(args, extra...)
	}

	log.Printf("[测速] 正在直连调用 CloudflareSpeedTest (已自动忽略本地代理环境变量): %s %s", binPath, strings.Join(args, " "))
	cmd := exec.Command(binPath, args...)
	cmd.Dir = absDir
	// Strip proxy environment variables so speedtest always measures direct local connectivity
	cmd.Env = buildDirectEnv(os.Environ())
	// Feed newline on stdin so Windows CloudflareSpeedTest never blocks waiting for Enter key
	cmd.Stdin = strings.NewReader("\r\n")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("[警告] CloudflareSpeedTest 进程返回非零状态 (%v), 尝试检查结果文件...", err)
	}

	ips, err := parseResultCSV(resultCSV, cfg.Top, cfg.Port, cfg.DisableD)
	if err != nil {
		return fmt.Errorf("解析测速结果失败: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("未筛选出任何符合条件的优选 IP，请放宽延迟(-tl)/速度(-sl)限制或检查本地网络")
	}

	log.Printf("[结果] 成功筛选出 %d 个优选 IP:", len(ips))
	for i, item := range ips {
		log.Printf("  #%d: %s:%d | 标签: %s (延迟: %s, 速度: %s)", i+1, item.IP, item.Port, item.Label, item.Latency, item.Speed)
	}

	if err := uploadPreferredIPs(apiURL, cfg.Token, ips); err != nil {
		return fmt.Errorf("上传优选 IP 到服务端失败: %w", err)
	}

	return nil
}

func buildDirectEnv(environ []string) []string {
	blocked := map[string]bool{
		"HTTP_PROXY":  true,
		"HTTPS_PROXY": true,
		"ALL_PROXY":   true,
		"http_proxy":  true,
		"https_proxy": true,
		"all_proxy":   true,
	}
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) > 0 && blocked[parts[0]] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func ensureCfstBinary(cfg *Config, absDir string) (string, error) {
	if cfg.CfstBin != "" {
		if st, err := os.Stat(cfg.CfstBin); err == nil && !st.IsDir() {
			return cfg.CfstBin, nil
		}
		return "", fmt.Errorf("指定的 -cfst-bin 文件不存在: %s", cfg.CfstBin)
	}

	candidates := []string{"cfst", "CloudflareSpeedTest"}
	if runtime.GOOS == "windows" {
		candidates = []string{"cfst.exe", "CloudflareSpeedTest.exe"}
	}

	for _, name := range candidates {
		p := filepath.Join(absDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if runtime.GOOS != "windows" {
				_ = os.Chmod(p, 0755)
			}
			return p, nil
		}
	}
	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	log.Printf("[下载] 本地未找到 CloudflareSpeedTest，正在根据当前平台 (%s/%s) 自动下载...", runtime.GOOS, runtime.GOARCH)
	if err := downloadAndExtractCfst(absDir); err != nil {
		return "", err
	}

	for _, name := range candidates {
		p := filepath.Join(absDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			_ = os.Chmod(p, 0755)
			return p, nil
		}
	}
	return "", errors.New("解压完成但未找到 CloudflareSpeedTest 可执行文件")
}

func downloadAndExtractCfst(destDir string) error {
	osName := runtime.GOOS
	archName := runtime.GOARCH

	switch archName {
	case "amd64", "arm64", "386":
	case "arm":
		archName = "armv7"
	default:
		return fmt.Errorf("暂不支持自动下载该架构 (%s/%s) 的 CloudflareSpeedTest，请手动下载后通过 -cfst-bin 指定", osName, archName)
	}

	ext := "tar.gz"
	if osName == "windows" || osName == "darwin" {
		ext = "zip"
	}

	fileName := fmt.Sprintf("cfst_%s_%s.%s", osName, archName, ext)
	baseURL := "https://github.com/XIU2/CloudflareSpeedTest/releases/latest/download/" + fileName
	downloadURLs := []string{
		baseURL,
		"https://ghfast.top/" + baseURL,
		"https://ghproxy.net/" + baseURL,
	}

	var lastErr error
	client := &http.Client{Timeout: 120 * time.Second}

	for _, u := range downloadURLs {
		log.Printf("[下载] 尝试拉取: %s", u)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "suoha-client/1.1")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		archiveData, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(archiveData) < 10240 {
			lastErr = fmt.Errorf("下载内容不完整 (%v)", err)
			continue
		}
		if ext == "zip" {
			err = extractZip(archiveData, destDir)
		} else {
			err = extractTarGz(archiveData, destDir)
		}
		if err != nil {
			lastErr = fmt.Errorf("解压校验失败 (%v)", err)
			continue
		}
		return nil
	}

	return fmt.Errorf("下载 %s 失败: %v", fileName, lastErr)
}

func extractZip(data []byte, destDir string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		outPath := filepath.Join(destDir, base)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(data []byte, destDir string) error {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := filepath.Base(hdr.Name)
		outPath := filepath.Join(destDir, base)
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		_, err = io.Copy(outFile, tr)
		outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func ensureIPRangeFile(path string, isIPv6 bool) error {
	if st, err := os.Stat(path); err == nil && st.Size() > 10 {
		return nil
	}
	ranges := defaultIPv4CIDRs
	if isIPv6 {
		ranges = defaultIPv6CIDRs
	}
	content := strings.Join(ranges, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}

func parseResultCSV(csvPath string, top int, port int, disableDownload bool) ([]PreferredIP, error) {
	raw, err := os.ReadFile(csvPath)
	if err != nil {
		return nil, err
	}
	// Strip UTF-8 BOM if present
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	r := csv.NewReader(bytes.NewReader(raw))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) <= 1 {
		return nil, nil
	}

	header := rows[0]
	ipIdx, lossIdx, latIdx, speedIdx, coloIdx := 0, 3, 4, 5, -1
	for i, col := range header {
		colName := strings.TrimSpace(col)
		switch {
		case strings.Contains(colName, "IP"):
			ipIdx = i
		case strings.Contains(colName, "丢包"):
			lossIdx = i
		case strings.Contains(colName, "延迟"):
			latIdx = i
		case strings.Contains(colName, "速度"):
			speedIdx = i
		case strings.Contains(colName, "地区") || strings.EqualFold(colName, "colo"):
			coloIdx = i
		}
	}

	var results []PreferredIP
	for _, row := range rows[1:] {
		if len(row) <= ipIdx {
			continue
		}
		ip := strings.TrimSpace(row[ipIdx])
		if ip == "" {
			continue
		}

		// Check packet loss if available
		if lossIdx >= 0 && lossIdx < len(row) {
			lossStr := strings.TrimSuffix(strings.TrimSpace(row[lossIdx]), "%")
			if lossVal, err := strconv.ParseFloat(lossStr, 64); err == nil {
				if lossVal > 0.60 {
					continue
				}
			}
		}

		var latFormatted string
		if latIdx >= 0 && latIdx < len(row) {
			latRaw := strings.TrimSpace(row[latIdx])
			if latVal, err := strconv.ParseFloat(latRaw, 64); err == nil && latVal > 0 {
				latFormatted = fmt.Sprintf("%dms", int(math.Round(latVal)))
			} else if latRaw != "" {
				latFormatted = latRaw
			}
		}

		var speedFormatted string
		if !disableDownload && speedIdx >= 0 && speedIdx < len(row) {
			speedRaw := strings.TrimSpace(row[speedIdx])
			if speedVal, err := strconv.ParseFloat(speedRaw, 64); err == nil && speedVal > 0 {
				speedFormatted = fmt.Sprintf("%.1fMB", speedVal)
			}
		}

		var colo string
		if coloIdx >= 0 && coloIdx < len(row) {
			colo = strings.TrimSpace(row[coloIdx])
			if colo == "N/A" || colo == "-" {
				colo = ""
			}
		}

		rank := len(results) + 1
		labelParts := []string{fmt.Sprintf("优选%d", rank)}
		if colo != "" {
			labelParts = append(labelParts, colo)
		}
		if latFormatted != "" {
			labelParts = append(labelParts, latFormatted)
		}
		if speedFormatted != "" {
			labelParts = append(labelParts, speedFormatted)
		}

		results = append(results, PreferredIP{
			IP:      ip,
			Port:    port,
			Latency: latFormatted,
			Speed:   speedFormatted,
			Colo:    colo,
			Label:   strings.Join(labelParts, "-"),
		})

		if len(results) >= top {
			break
		}
	}

	return results, nil
}

func uploadPreferredIPs(apiURL string, token string, ips []PreferredIP) error {
	payload := UploadPayload{IPs: ips}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Uses http.ProxyFromEnvironment by default so upload respects system proxy if configured
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest("POST", apiURL, bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "suoha-client/1.0")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[上传] 第 %d/3 次请求失败 (%v)，稍后重试...", attempt, err)
			time.Sleep(time.Duration(attempt*2) * time.Second)
			continue
		}

		respBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
			if resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("Token 鉴权失败 (HTTP 401)，请核对服务端 /etc/suoha_sub_token: %s", string(respBytes))
			}
			time.Sleep(time.Duration(attempt*2) * time.Second)
			continue
		}

		var res UploadResponse
		if err := json.Unmarshal(respBytes, &res); err == nil && res.OK {
			log.Printf("[成功] 服务端优选列表已更新! 共生效 %d 个优选 IP，更新时间: %s，订阅文件已自动重生成。", res.Count, res.UpdatedAt)
			return nil
		}
		log.Printf("[成功] 服务端返回: %s", strings.TrimSpace(string(respBytes)))
		return nil
	}

	return lastErr
}
