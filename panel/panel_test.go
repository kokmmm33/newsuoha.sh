package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/proxy"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/server"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/subgen"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/supervisor"
)

func TestPasswordHashing(t *testing.T) {
	hash, err := config.HashPassword("S3cretPass!")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !config.VerifyPassword("S3cretPass!", hash) {
		t.Fatalf("VerifyPassword returned false for valid password")
	}
	if config.VerifyPassword("wrongpass", hash) {
		t.Fatalf("VerifyPassword returned true for wrong password")
	}
}

func TestLegacyMigrationAndBatchParse(t *testing.T) {
	tmp := t.TempDir()
	etcDir := filepath.Join(tmp, "etc")
	webDir := filepath.Join(tmp, "www")
	dataDir := filepath.Join(tmp, "opt_suoha")
	_ = os.MkdirAll(etcDir, 0755)
	_ = os.MkdirAll(webDir, 0755)

	legacy := config.LegacyPaths{
		PortFile:  filepath.Join(etcDir, "suoha_sub_port"),
		UUIDFile:  filepath.Join(etcDir, "suoha_sub_uuid"),
		TokenFile: filepath.Join(etcDir, "suoha_sub_token"),
		WebDir:    webDir,
	}

	_ = os.WriteFile(legacy.PortFile, []byte("28888\n"), 0644)
	_ = os.WriteFile(legacy.UUIDFile, []byte("legacy-sub-uuid-1234\n"), 0644)
	_ = os.WriteFile(legacy.TokenFile, []byte("legacytok999\n"), 0600)

	meta := `{
		"mode": "installed",
		"uuid": "11111111-2222-3333-4444-555555555555",
		"argo_vl": "node.example.com",
		"urlpath_vless": "vl-custom",
		"urlpath_trojan": "tr-custom",
		"node_tag": "HKG-Test",
		"ss": {
			"ipv6_addr": "2400:cb00::1234",
			"ss_port": 34567,
			"ss_method": "aes-128-gcm",
			"ss_password": "sspwd"
		}
	}`
	_ = os.WriteFile(filepath.Join(webDir, "meta.json"), []byte(meta), 0644)
	_ = os.WriteFile(filepath.Join(webDir, "preferred_ips.json"), []byte(`{"updated_at":"2026-11-06 12:00:00","ips":[{"ip":"104.16.1.1","port":443,"label":"优选1"}]}`), 0644)

	store, err := config.LoadOrInit(dataDir, legacy, true)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}

	cfg := store.GetConfig()
	if cfg.ListenPort != 28888 {
		t.Errorf("expected migrated port 28888, got %d", cfg.ListenPort)
	}
	if cfg.SubUUID != "legacy-sub-uuid-1234" {
		t.Errorf("expected migrated SubUUID, got %q", cfg.SubUUID)
	}
	if cfg.ClientToken != "legacytok999" {
		t.Errorf("expected migrated ClientToken, got %q", cfg.ClientToken)
	}
	if cfg.Tunnel.Mode != "token" || cfg.Tunnel.CustomDomain != "node.example.com" {
		t.Errorf("expected migrated installed custom domain, got mode=%q domain=%q", cfg.Tunnel.Mode, cfg.Tunnel.CustomDomain)
	}
	if !cfg.Protocols.IPv6SSEnabled || cfg.Protocols.IPv6Addr != "2400:cb00::1234" || cfg.Protocols.SSPort != 34567 {
		t.Errorf("expected migrated IPv6 SS settings, got %+v", cfg.Protocols)
	}
	pref := store.GetPreferred()
	if len(pref.IPs) != 1 || pref.IPs[0].IP != "104.16.1.1" {
		t.Errorf("expected migrated preferred IPs, got %+v", pref.IPs)
	}

	// Test batch preferred IP text parser
	batch := config.ParseBatchPreferredText(`
104.16.10.1
104.16.10.2:2053#香港高速
[2606:4700::88]:8443#IPv6优选
`, 443)
	if len(batch) != 3 {
		t.Fatalf("expected 3 batch parsed IPs, got %d", len(batch))
	}
	if batch[1].Port != 2053 || batch[1].Label != "香港高速" {
		t.Errorf("unexpected 2nd batch item: %+v", batch[1])
	}
	if batch[2].IP != "2606:4700::88" || batch[2].Port != 8443 {
		t.Errorf("unexpected IPv6 batch item: %+v", batch[2])
	}
}

func TestSubscriptionGeneration(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Protocols.IPv6SSEnabled = true
		d.Protocols.IPv6Addr = "2400:cb00::99"
		d.Protocols.SSPort = 35000
		return nil
	})
	_, _ = store.SetPreferredIPs([]config.PreferredIP{
		{IP: "104.16.8.8", Port: 2053, Colo: "HKG", Latency: "32ms", Label: "优选1-HKG-32ms"},
	}, "client")

	rt := subgen.RuntimeState{
		ArgoVL:    "quick-test.trycloudflare.com",
		ArgoTR:    "quick-test.trycloudflare.com",
		ArgoPanel: "quick-test.trycloudflare.com",
		ServerIP:  "1.2.3.4",
	}
	bundle := subgen.Generate(store.GetConfig(), store.GetPreferred(), rt)

	// 1 preferred + 1 default argo + 2 fallbacks = 4 per WS protocol => 8 WS + 1 IPv6 SS = 9 total nodes
	if len(bundle.Nodes) != 9 {
		t.Fatalf("expected 9 generated nodes, got %d", len(bundle.Nodes))
	}
	decoded, err := base64.StdEncoding.DecodeString(bundle.SubBase64)
	if err != nil {
		t.Fatalf("failed to base64 decode sub.txt: %v", err)
	}
	if !strings.Contains(string(decoded), "vless://") || !strings.Contains(string(decoded), "trojan://") || !strings.Contains(string(decoded), "ss://") {
		t.Errorf("sub.txt missing expected protocol URIs: %s", string(decoded))
	}
	if !strings.Contains(bundle.ClashYAML, "type: url-test") || !strings.Contains(bundle.ClashYAML, "AUTO-优选自动测速") {
		t.Errorf("clash.yaml missing AUTO url-test group:\n%s", bundle.ClashYAML)
	}
	for _, expected := range []string{
		"rule-providers:",
		"format: mrs",
		"AI-人工智能",
		"Streaming-流媒体",
		"RULE-SET,ai_domain,AI-人工智能",
		"RULE-SET,cn_ip,CN-国内直连,no-resolve",
		"MATCH,FINAL-漏网之鱼",
	} {
		if !strings.Contains(bundle.ClashYAML, expected) {
			t.Errorf("clash.yaml missing smart routing fragment %q", expected)
		}
	}
	if bundle.ArgoSubURL == "" || !strings.HasPrefix(bundle.ArgoSubURL, "https://quick-test.trycloudflare.com/") {
		t.Errorf("expected HTTPS Argo subscription URL, got %q", bundle.ArgoSubURL)
	}
}

func TestWebSocketReverseProxy(t *testing.T) {
	// Start a mock local Xray WebSocket server that upgrades connection and echoes payload
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	upPort := upLn.Addr().(*net.TCPAddr).Port

	upMux := http.NewServeMux()
	upMux.HandleFunc("/vl-testpath", func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("ResponseWriter does not support Hijacker")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = rw.Flush()
		line, _ := rw.ReadString('\n')
		_, _ = rw.WriteString("ECHO:" + line)
		_ = rw.Flush()
	})
	upSrv := &http.Server{Handler: upMux}
	go func() { _ = upSrv.Serve(upLn) }()
	defer upSrv.Close()

	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Protocols.VLESSPath = "vl-testpath"
		d.Protocols.VLESSLocalPort = upPort
		return nil
	})

	disp := proxy.NewWSDispatcher(store)
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !disp.TryServe(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer gw.Close()

	// Dial gateway with raw TCP and perform WebSocket HTTP Upgrade + duplex stream exchange
	gwAddr := strings.TrimPrefix(gw.URL, "http://")
	conn, err := net.Dial("tcp", gwAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reqRaw := fmt.Sprintf("GET /vl-testpath?ed=2048 HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", gwAddr)
	if _, err := conn.Write([]byte(reqRaw)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("expected HTTP 101 Switching Protocols, got %q (err=%v)", statusLine, err)
	}
	// Drain headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("hello-vless-stream\n")); err != nil {
		t.Fatal(err)
	}
	echoed, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(echoed) != "ECHO:hello-vless-stream" {
		t.Errorf("expected bidirectional WS stream 'ECHO:hello-vless-stream', got %q", echoed)
	}
}

func TestServerAuthClientAPIAndArgoGuard(t *testing.T) {
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	initPwd := store.InitialGeneratedPassword()
	logs := supervisor.NewRingLog(50)
	mgr := supervisor.NewManager(store, logs, nil)

	h, err := server.NewHandler(store, mgr, embeddedWebFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	cfg := store.GetConfig()

	// 1. Root page returns embedded index.html
	resRoot, err := http.Get(ts.URL + "/")
	if err != nil || resRoot.StatusCode != http.StatusOK {
		t.Fatalf("GET / failed: %v", err)
	}
	rootBody, _ := io.ReadAll(resRoot.Body)
	resRoot.Body.Close()
	if !bytes.Contains(rootBody, []byte("New-Suoha")) {
		t.Errorf("expected embedded Web UI HTML")
	}

	// 2. Protected admin endpoint rejects unauthenticated requests
	resUnauth, _ := http.Get(ts.URL + "/api/admin/overview")
	resUnauth.Body.Close()
	if resUnauth.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on /api/admin/overview without session, got %d", resUnauth.StatusCode)
	}

	// 3. suoha-client POST /api/update_ips works with ClientToken
	updateReq, _ := http.NewRequest("POST", ts.URL+"/api/update_ips", strings.NewReader(`{"ips":[{"ip":"172.67.10.20","port":443,"colo":"SJC","latency":"40ms","speed":"25MB"}]}`))
	updateReq.Header.Set("Authorization", "Bearer "+cfg.ClientToken)
	updateReq.Header.Set("Content-Type", "application/json")
	updateRes, err := http.DefaultClient.Do(updateReq)
	if err != nil || updateRes.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/update_ips failed: status=%v err=%v", updateRes.StatusCode, err)
	}
	updateRes.Body.Close()

	// 4. Subscription URL reflects newly uploaded preferred IP
	subRes, err := http.Get(fmt.Sprintf("%s/%s/clash.yaml", ts.URL, cfg.SubUUID))
	if err != nil || subRes.StatusCode != http.StatusOK {
		t.Fatalf("GET clash.yaml failed")
	}
	subRes.Body.Close()

	// 5. Login with initial password succeeds and sets session cookie
	loginBody := fmt.Sprintf(`{"username":%q,"password":%q}`, cfg.AdminUser, initPwd)
	loginRes, err := http.Post(ts.URL+"/api/admin/login", "application/json", strings.NewReader(loginBody))
	if err != nil || loginRes.StatusCode != http.StatusOK {
		t.Fatalf("admin login failed: status=%v err=%v", loginRes.StatusCode, err)
	}
	cookies := loginRes.Cookies()
	loginRes.Body.Close()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after login")
	}

	ovReq, _ := http.NewRequest("GET", ts.URL+"/api/admin/overview", nil)
	ovReq.AddCookie(cookies[0])
	ovRes, err := http.DefaultClient.Do(ovReq)
	if err != nil || ovRes.StatusCode != http.StatusOK {
		t.Fatalf("authenticated GET /api/admin/overview failed")
	}
	var ovData map[string]any
	_ = json.NewDecoder(ovRes.Body).Decode(&ovData)
	ovRes.Body.Close()
	if ovData["ok"] != true {
		t.Errorf("expected ok=true in overview payload")
	}
	helperMap, _ := ovData["client_helper"].(map[string]any)
	if helperMap == nil || !strings.Contains(fmt.Sprint(helperMap["auto_unix_once"]), "/api/client.sh") {
		t.Errorf("expected auto_unix_once in overview client_helper, got %+v", helperMap)
	}

	// 6. Client bootstrap scripts (/api/client.sh & /api/client.ps1) enforce token auth and emit exact Release asset logic
	unauthSh, _ := http.Get(ts.URL + "/api/client.sh")
	unauthSh.Body.Close()
	if unauthSh.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on /api/client.sh without token, got %d", unauthSh.StatusCode)
	}

	shRes, err := http.Get(fmt.Sprintf("%s/api/client.sh?token=%s&once=1", ts.URL, cfg.ClientToken))
	if err != nil || shRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/client.sh with token failed: status=%v err=%v", shRes.StatusCode, err)
	}
	shBody, _ := io.ReadAll(shRes.Body)
	shRes.Body.Close()
	shText := string(shBody)
	for _, needle := range []string{`ASSET="suoha-client-${GOOS}-${GOARCH}"`, `chmod +x "$BIN_PATH"`, `xattr -cr`, `-once`} {
		if !strings.Contains(shText, needle) {
			t.Errorf("expected /api/client.sh output to contain %q", needle)
		}
	}

	psRes, err := http.Get(fmt.Sprintf("%s/api/client.ps1?token=%s&once=1", ts.URL, cfg.ClientToken))
	if err != nil || psRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/client.ps1 with token failed: status=%v err=%v", psRes.StatusCode, err)
	}
	psBody, _ := io.ReadAll(psRes.Body)
	psRes.Body.Close()
	psText := string(psBody)
	for _, needle := range []string{`suoha-client-windows-$Arch.exe`, `Unblock-File`, `"-once"`} {
		if !strings.Contains(psText, needle) {
			t.Errorf("expected /api/client.ps1 output to contain %q", needle)
		}
	}

	// 7. When AllowArgoPanel is disabled, loopback requests bearing Cf-Connecting-Ip get 404 on /, while subscription & client.sh URLs still return 200!
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.AllowArgoPanel = false
		return nil
	})
	cfPanelReq, _ := http.NewRequest("GET", ts.URL+"/", nil)
	cfPanelReq.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	cfPanelRes, _ := http.DefaultClient.Do(cfPanelReq)
	cfPanelRes.Body.Close()
	if cfPanelRes.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 on / via Argo when AllowArgoPanel=false, got %d", cfPanelRes.StatusCode)
	}

	cfSubReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/%s/sub.txt", ts.URL, cfg.SubUUID), nil)
	cfSubReq.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	cfSubRes, _ := http.DefaultClient.Do(cfSubReq)
	cfSubRes.Body.Close()
	if cfSubRes.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on subscription via Argo even when AllowArgoPanel=false, got %d", cfSubRes.StatusCode)
	}

	cfBootstrapReq, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/client.sh?token=%s", ts.URL, cfg.ClientToken), nil)
	cfBootstrapReq.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	cfBootstrapRes, _ := http.DefaultClient.Do(cfBootstrapReq)
	cfBootstrapRes.Body.Close()
	if cfBootstrapRes.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on /api/client.sh via Argo even when AllowArgoPanel=false, got %d", cfBootstrapRes.StatusCode)
	}
}
