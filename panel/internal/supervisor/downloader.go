package supervisor

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var downloadMu sync.Mutex

// EnsureXrayBinary locates or downloads the Xray-core binary into <dataDir>/bin/xray.
func EnsureXrayBinary(dataDir string, logger *RingLog) (string, error) {
	downloadMu.Lock()
	defer downloadMu.Unlock()

	binDir := filepath.Join(dataDir, "bin")
	target := filepath.Join(binDir, "xray")
	if isExecutableFile(target) {
		return target, nil
	}

	// Check legacy or system locations first to avoid unnecessary re-downloads
	candidates := []string{
		filepath.Join(dataDir, "xray"),
		"/opt/suoha/xray",
		"/opt/suoha_quick/xray/xray",
	}
	for _, c := range candidates {
		if isExecutableFile(c) {
			return c, nil
		}
	}
	if p, err := exec.LookPath("xray"); err == nil && isExecutableFile(p) {
		return p, nil
	}

	var zipName string
	switch runtime.GOARCH {
	case "amd64":
		zipName = "Xray-linux-64.zip"
	case "386":
		zipName = "Xray-linux-32.zip"
	case "arm64":
		zipName = "Xray-linux-arm64-v8a.zip"
	case "arm":
		zipName = "Xray-linux-arm32-v7a.zip"
	default:
		return "", fmt.Errorf("当前架构 %s 暂不支持自动下载 Xray-core", runtime.GOARCH)
	}

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}

	rawURL := "https://github.com/XTLS/Xray-core/releases/latest/download/" + zipName
	logger.Add("panel", fmt.Sprintf("本地未检测到 Xray 内核，正在下载 %s ...", zipName))
	data, err := downloadWithMirrors(rawURL, logger)
	if err != nil {
		return "", fmt.Errorf("下载 Xray 失败: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("解压 Xray 压缩包失败: %w", err)
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(f.Name)
		if base != "xray" && base != "geoip.dat" && base != "geosite.dat" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		outPath := filepath.Join(binDir, base)
		perm := os.FileMode(0644)
		if base == "xray" {
			perm = 0755
		}
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
		if err != nil {
			rc.Close()
			return "", err
		}
		_, copyErr := io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if copyErr != nil {
			return "", copyErr
		}
	}

	if !isExecutableFile(target) {
		return "", fmt.Errorf("解压完成但未找到可执行文件 %s", target)
	}
	logger.Add("panel", "Xray-core 内核准备就绪")
	return target, nil
}

// EnsureCloudflaredBinary locates or downloads the cloudflared binary into <dataDir>/bin/cloudflared.
func EnsureCloudflaredBinary(dataDir string, logger *RingLog) (string, error) {
	downloadMu.Lock()
	defer downloadMu.Unlock()

	binDir := filepath.Join(dataDir, "bin")
	target := filepath.Join(binDir, "cloudflared")
	if isExecutableFile(target) {
		return target, nil
	}

	candidates := []string{
		filepath.Join(dataDir, "cloudflared-linux"),
		"/opt/suoha/cloudflared-linux",
		"/opt/suoha_quick/cloudflared-linux",
	}
	for _, c := range candidates {
		if isExecutableFile(c) {
			return c, nil
		}
	}
	if p, err := exec.LookPath("cloudflared"); err == nil && isExecutableFile(p) {
		return p, nil
	}

	var binName string
	switch runtime.GOARCH {
	case "amd64":
		binName = "cloudflared-linux-amd64"
	case "386":
		binName = "cloudflared-linux-386"
	case "arm64":
		binName = "cloudflared-linux-arm64"
	case "arm":
		binName = "cloudflared-linux-arm"
	default:
		return "", fmt.Errorf("当前架构 %s 暂不支持自动下载 cloudflared", runtime.GOARCH)
	}

	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}

	rawURL := "https://github.com/cloudflare/cloudflared/releases/latest/download/" + binName
	logger.Add("panel", fmt.Sprintf("本地未检测到 cloudflared，正在下载 %s ...", binName))
	data, err := downloadWithMirrors(rawURL, logger)
	if err != nil {
		return "", fmt.Errorf("下载 cloudflared 失败: %w", err)
	}

	tmpPath := target + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0755); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return "", err
	}
	logger.Add("panel", "cloudflared 内核准备就绪")
	return target, nil
}

func downloadWithMirrors(rawURL string, logger *RingLog) ([]byte, error) {
	urls := []string{
		rawURL,
		"https://ghfast.top/" + rawURL,
		"https://ghproxy.net/" + rawURL,
	}
	client := &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "suoha-panel/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, u)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(body) < 4096 {
			lastErr = fmt.Errorf("下载数据不完整 (%d bytes)", len(body))
			continue
		}
		return body, nil
	}
	if logger != nil && lastErr != nil {
		logger.Add("panel", fmt.Sprintf("内核下载失败: %v", lastErr))
	}
	return nil, lastErr
}

func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() < 1024 {
		return false
	}
	return st.Mode()&0111 != 0
}
