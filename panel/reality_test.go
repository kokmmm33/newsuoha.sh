package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/server"
	"github.com/kokmmm33/newsuoha.sh/panel/internal/supervisor"
)

func TestRealityKeyPairAndConfigDefaults(t *testing.T) {
	priv, pub, err := config.GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("GenerateRealityKeyPair failed: %v", err)
	}
	if len(priv) != 43 || len(pub) != 43 {
		t.Fatalf("expected 43-char raw base64url X25519 keys, got priv=%d pub=%d", len(priv), len(pub))
	}

	rawPriv, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(rawPriv) != 32 {
		t.Fatalf("invalid raw private key: err=%v len=%d", err, len(rawPriv))
	}
	// Verify RFC 7748 clamping matches Xray-core x25519 expectation
	if rawPriv[0]&7 != 0 || rawPriv[31]&128 != 0 || rawPriv[31]&64 == 0 {
		t.Errorf("X25519 private key not clamped per RFC 7748")
	}

	normPriv, derivedPub, err := config.DeriveRealityPublicKey(priv)
	if err != nil {
		t.Fatalf("DeriveRealityPublicKey failed: %v", err)
	}
	if normPriv != priv || derivedPub != pub {
		t.Errorf("DeriveRealityPublicKey mismatch: got (%q, %q), want (%q, %q)", normPriv, derivedPub, priv, pub)
	}

	// Verify fresh Store defaults use Apple domain www.apple.com
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatalf("LoadOrInit failed: %v", err)
	}
	cfg := store.GetConfig()
	if cfg.Protocols.RealitySNI != "www.apple.com" {
		t.Errorf("expected default RealitySNI 'www.apple.com', got %q", cfg.Protocols.RealitySNI)
	}
	if cfg.Protocols.RealityPrivateKey == "" || cfg.Protocols.RealityPublicKey == "" {
		t.Errorf("expected pre-generated Reality keypair in fresh config")
	}
	if len(cfg.Protocols.RealityShortID) < 2 || len(cfg.Protocols.RealityShortID)%2 != 0 {
		t.Errorf("expected even-length hex RealityShortID, got %q", cfg.Protocols.RealityShortID)
	}

	// Domain & ShortID sanitization edge cases
	if got := config.ExtractRealityDomain("https://ITUNES.apple.com:443/us/app"); got != "itunes.apple.com" {
		t.Errorf("ExtractRealityDomain failed: got %q", got)
	}
	if got := config.SanitizeRealitySNI("invalid_host.."); got != "www.apple.com" {
		t.Errorf("SanitizeRealitySNI should fallback to www.apple.com, got %q", got)
	}
	if got := config.SanitizeRealityShortID("abc"); got != "0abc" {
		t.Errorf("SanitizeRealityShortID should pad odd hex to even length, got %q", got)
	}
	for _, legacyFP := range []string{"ios", "edge", "random", "qq", ""} {
		if got := config.SanitizeRealityFingerprint(legacyFP); got != "chrome" {
			t.Errorf("SanitizeRealityFingerprint(%q) should normalize to 'chrome', got %q", legacyFP, got)
		}
	}
}

func TestBuildXrayConfigRealityInbound(t *testing.T) {
	priv, _, err := config.GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	proto := config.ProtocolConfig{
		UUID:              "11111111-2222-4333-8444-555555555555",
		RealityEnabled:    true,
		RealityPort:       24443,
		RealitySNI:        "www.apple.com",
		RealityPrivateKey: priv,
		RealityShortID:    "a1b2c3d4",
		VLESSEnabled:      false,
		TrojanEnabled:     false,
	}

	doc := supervisor.BuildXrayConfig(proto)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json.Marshal BuildXrayConfig failed: %v", err)
	}
	var parsed struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Settings struct {
				Decryption string `json:"decryption"`
				Clients    []struct {
					ID   string `json:"id"`
					Flow string `json:"flow"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Network         string `json:"network"`
				Security        string `json:"security"`
				RealitySettings struct {
					Dest        string   `json:"dest"`
					ServerNames []string `json:"serverNames"`
					PrivateKey  string   `json:"privateKey"`
					ShortIds    []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
			Sniffing struct {
				Enabled   bool `json:"enabled"`
				RouteOnly bool `json:"routeOnly"`
			} `json:"sniffing"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("json.Unmarshal Xray config failed: %v", err)
	}
	if len(parsed.Inbounds) != 1 {
		t.Fatalf("expected exactly 1 Reality inbound when VLESS-WS/Trojan-WS disabled, got %d", len(parsed.Inbounds))
	}

	inb := parsed.Inbounds[0]
	if inb.Tag != "vless-reality-in" || inb.Protocol != "vless" || inb.Port != 24443 {
		t.Errorf("unexpected inbound header: %+v", inb)
	}
	if len(inb.Settings.Clients) != 1 || inb.Settings.Clients[0].Flow != "xtls-rprx-vision" {
		t.Errorf("expected flow=xtls-rprx-vision, got %+v", inb.Settings.Clients)
	}
	rs := inb.StreamSettings.RealitySettings
	if inb.StreamSettings.Security != "reality" || rs.Dest != "www.apple.com:443" {
		t.Errorf("unexpected realitySettings dest/security: security=%q dest=%q", inb.StreamSettings.Security, rs.Dest)
	}
	if len(rs.ServerNames) != 1 || rs.ServerNames[0] != "www.apple.com" {
		t.Errorf("unexpected serverNames: %+v", rs.ServerNames)
	}
	if rs.PrivateKey != priv || len(rs.ShortIds) != 1 || rs.ShortIds[0] != "a1b2c3d4" {
		t.Errorf("unexpected privateKey/shortIds: %+v", rs)
	}
	if !inb.Sniffing.Enabled || !inb.Sniffing.RouteOnly {
		t.Errorf("expected sniffing enabled with routeOnly=true, got %+v", inb.Sniffing)
	}
}

func startLocalMockTLSServer(t *testing.T, dnsNames []string, minVer, maxVer uint16, alpn []string) (string, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName:   dnsNames[0],
			Organization: []string{"Apple Inc. Test CA"},
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certObj, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certObj)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  caKey,
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   minVer,
		MaxVersion:   maxVer,
		NextProtos:   alpn,
	}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)
	t.Cleanup(func() { _ = tlsLn.Close() })

	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(c)
		}
	}()

	return rawLn.Addr().String(), pool
}

func TestRealityDomainScannerProbeAndAdminAPI(t *testing.T) {
	// 1. Valid TLS 1.3 + HTTP/2 (h2) target server
	goodAddr, goodPool := startLocalMockTLSServer(
		t,
		[]string{"www.apple.com", "custom.apple-cdn.example"},
		tls.VersionTLS13,
		tls.VersionTLS13,
		[]string{"h2", "http/1.1"},
	)

	ctx := context.Background()
	reportGood := supervisor.ScanRealityDomains(ctx, supervisor.RealityScanOptions{
		Mode:             "custom",
		CustomDomains:    []string{"www.apple.com", "custom.apple-cdn.example"},
		RootCAs:          goodPool,
		DialAddrOverride: goodAddr,
		AllowPrivateIP:   true,
	})
	if reportGood.Scanned != 2 || reportGood.ValidCount != 2 {
		t.Fatalf("expected 2 valid TLS1.3+H2 domains, got scanned=%d valid=%d results=%+v",
			reportGood.Scanned, reportGood.ValidCount, reportGood.Results)
	}
	for _, r := range reportGood.Results {
		if !r.Valid || !r.TLS13 || !r.H2 {
			t.Errorf("expected domain %q to be valid TLS1.3+H2, got %+v", r.Domain, r)
		}
	}

	// 2. Incompatible target server (TLS 1.2 only, no h2) must be rejected
	badAddr, badPool := startLocalMockTLSServer(
		t,
		[]string{"legacy.example.org"},
		tls.VersionTLS12,
		tls.VersionTLS12,
		[]string{"http/1.1"},
	)
	badRes := supervisor.ProbeRealityDomain(ctx, "legacy.example.org", "Custom", supervisor.RealityScanOptions{
		RootCAs:          badPool,
		DialAddrOverride: badAddr,
		AllowPrivateIP:   true,
	})
	if badRes.Valid {
		t.Errorf("expected TLS 1.2 / non-H2 domain to be rejected, got %+v", badRes)
	}
	if badRes.Reason == "" {
		t.Errorf("expected diagnostic reason when domain fails Reality check")
	}

	// 3. Admin HTTP API: /api/admin/protocols/apply, /api/admin/rotate (reality_keys), /api/admin/reality/scan
	tmp := t.TempDir()
	store, err := config.LoadOrInit(tmp, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	initPwd := store.InitialGeneratedPassword()
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Protocols.ServerHostOverride = "203.0.113.88"
		return nil
	})

	logs := supervisor.NewRingLog(50)
	mgr := supervisor.NewManager(store, logs, nil)
	h, err := server.NewHandler(store, mgr, embeddedWebFS, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	cfg := store.GetConfig()
	loginRes, err := http.Post(
		ts.URL+"/api/admin/login",
		"application/json",
		strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, cfg.AdminUser, initPwd)),
	)
	if err != nil || loginRes.StatusCode != http.StatusOK {
		t.Fatalf("admin login failed: %v", err)
	}
	cookie := loginRes.Cookies()[0]
	loginRes.Body.Close()

	doAdminPost := func(path string, payload any) (*http.Response, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		resp, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil {
			t.Fatalf("POST %s failed: %v", path, reqErr)
		}
		defer resp.Body.Close()
		var out map[string]any
		rawBody, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(rawBody, &out)
		return resp, out
	}

	// Reject port conflict with panel ListenPort
	conflictProto := cfg.Protocols
	conflictProto.RealityEnabled = true
	conflictProto.RealityPort = cfg.ListenPort
	respConflict, _ := doAdminPost("/api/admin/protocols/apply", conflictProto)
	if respConflict.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 when RealityPort equals ListenPort, got %d", respConflict.StatusCode)
	}

	// Reject invalid SNI domain
	badSNIProto := cfg.Protocols
	badSNIProto.RealitySNI = "not_a_valid_domain.."
	respBadSNI, _ := doAdminPost("/api/admin/protocols/apply", badSNIProto)
	if respBadSNI.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid RealitySNI, got %d", respBadSNI.StatusCode)
	}

	// Rotate Reality X25519 keypair & ShortID
	respRot, rotData := doAdminPost("/api/admin/rotate", map[string]any{"target": "reality_keys"})
	if respRot.StatusCode != http.StatusOK || rotData["ok"] != true {
		t.Fatalf("rotate reality_keys failed: status=%d data=%+v", respRot.StatusCode, rotData)
	}
	newPub := fmt.Sprint(rotData["public_key"])
	newPriv := fmt.Sprint(rotData["private_key"])
	newSID := fmt.Sprint(rotData["short_id"])
	if len(newPub) != 43 || len(newPriv) != 43 || len(newSID) < 2 {
		t.Fatalf("unexpected rotated reality keys: %+v", rotData)
	}

	// Update custom SNI via /api/admin/protocols/apply (keep RealityEnabled=false here so ReloadXray doesn't attempt network binary download in unit test)
	updatedProto := store.GetConfig().Protocols
	updatedProto.RealitySNI = "updates.cdn-apple.com"
	updatedProto.RealityPort = 28443
	respApply, applyData := doAdminPost("/api/admin/protocols/apply", updatedProto)
	if respApply.StatusCode != http.StatusOK || applyData["ok"] != true {
		t.Fatalf("protocols/apply failed: status=%d data=%+v", respApply.StatusCode, applyData)
	}
	if gotSNI := store.GetConfig().Protocols.RealitySNI; gotSNI != "updates.cdn-apple.com" {
		t.Errorf("expected persisted RealitySNI 'updates.cdn-apple.com', got %q", gotSNI)
	}

	// Enable Reality in store and verify live subscription endpoints emit VLESS+Reality+Vision with rotated key & custom SNI
	_, _ = store.UpdateConfig(func(d *config.PanelConfig) error {
		d.Protocols.RealityEnabled = true
		return nil
	})
	h.SyncStaticSubscriptions()

	clashRes, err := http.Get(fmt.Sprintf("%s/%s/clash.yaml", ts.URL, cfg.SubUUID))
	if err != nil || clashRes.StatusCode != http.StatusOK {
		t.Fatalf("GET clash.yaml failed: %v", err)
	}
	clashBody, _ := io.ReadAll(clashRes.Body)
	clashRes.Body.Close()
	clashText := string(clashBody)
	for _, want := range []string{
		"flow: xtls-rprx-vision",
		`servername: "updates.cdn-apple.com"`,
		`client-fingerprint: "chrome"`,
		fmt.Sprintf("public-key: %q", newPub),
		fmt.Sprintf("short-id: %q", newSID),
		"support-x25519mlkem768: true",
	} {
		if !strings.Contains(clashText, want) {
			t.Errorf("clash.yaml missing %q:\n%s", want, clashText)
		}
	}

	// Verify User-Agent aware Reality fingerprint emission on sub.txt / nodes.txt / clash.yaml
	fetchSubWithUA := func(fname, ua string) (string, http.Header) {
		t.Helper()
		req, reqErr := http.NewRequest("GET", fmt.Sprintf("%s/%s/%s", ts.URL, cfg.SubUUID, fname), nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		res, reqErr := http.DefaultClient.Do(req)
		if reqErr != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s (UA=%q) failed: err=%v status=%v", fname, ua, reqErr, res)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return string(b), res.Header
	}

	srSubB64, srHdr := fetchSubWithUA("sub.txt", "Shadowrocket/2.2.93 CFNetwork/1568.200.51 Darwin/24.1.0")
	if gotVary := srHdr.Get("Vary"); !strings.Contains(gotVary, "User-Agent") {
		t.Errorf("expected Vary: User-Agent header on subscription response, got %q", gotVary)
	}
	srSubDecoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(srSubB64))
	if err != nil {
		t.Fatalf("base64 decode Shadowrocket sub.txt failed: %v", err)
	}
	srNodesTxt, _ := fetchSubWithUA("nodes.txt", "Shadowrocket/2.2.93 CFNetwork/1568.200.51 Darwin/24.1.0")
	if string(srSubDecoded) != srNodesTxt {
		t.Errorf("Shadowrocket decoded sub.txt != nodes.txt:\nsub=%q\nnodes=%q", string(srSubDecoded), srNodesTxt)
	}
	if !strings.Contains(srNodesTxt, "security=reality") || !strings.Contains(srNodesTxt, "&fp=chrome140&") || strings.Contains(srNodesTxt, "&fp=chrome&") {
		t.Errorf("expected Shadowrocket Reality subscription to emit fp=chrome140 instead of fp=chrome, got:\n%s", srNodesTxt)
	}

	srClashTxt, _ := fetchSubWithUA("clash.yaml", "Shadowrocket/2.2.93 CFNetwork/1568.200.51 Darwin/24.1.0")
	if strings.Contains(srClashTxt, "chrome140") || !strings.Contains(srClashTxt, `client-fingerprint: "chrome"`) {
		t.Errorf("clash.yaml must retain client-fingerprint: chrome regardless of User-Agent:\n%s", srClashTxt)
	}

	// Verify static files on disk were NOT polluted with fp=chrome140 after Shadowrocket HTTP fetch
	diskNodesBytes, err := os.ReadFile(filepath.Join(tmp, "sub", cfg.SubUUID, "nodes.txt"))
	if err != nil {
		t.Fatalf("read static nodes.txt failed: %v", err)
	}
	if !strings.Contains(string(diskNodesBytes), "&fp=chrome&") || strings.Contains(string(diskNodesBytes), "chrome140") {
		t.Errorf("static on-disk nodes.txt must keep canonical fp=chrome, got:\n%s", string(diskNodesBytes))
	}

	// Verify non-Shadowrocket clients continue receiving canonical fp=chrome
	xrayNodesTxt, _ := fetchSubWithUA("nodes.txt", "v2rayNG/1.9.16")
	if !strings.Contains(xrayNodesTxt, "&fp=chrome&") || strings.Contains(xrayNodesTxt, "chrome140") {
		t.Errorf("expected v2rayNG Reality subscription to receive fp=chrome, got:\n%s", xrayNodesTxt)
	}

	uiRes, err := http.Get(ts.URL + "/")
	if err != nil || uiRes.StatusCode != http.StatusOK {
		t.Fatalf("GET / failed: %v", err)
	}
	uiBody, _ := io.ReadAll(uiRes.Body)
	uiRes.Body.Close()
	if strings.Contains(string(uiBody), "proto-reality-fp") {
		t.Errorf("index.html should not expose proto-reality-fp selector")
	}

	// Verify /api/admin/reality/scan endpoint structure
	respScan, scanData := doAdminPost("/api/admin/reality/scan", map[string]any{
		"mode":   "custom",
		"custom": "127.0.0.1",
	})
	if respScan.StatusCode != http.StatusOK || scanData["ok"] != true {
		t.Fatalf("POST /api/admin/reality/scan failed: status=%d data=%+v", respScan.StatusCode, scanData)
	}
	reportMap, _ := scanData["report"].(map[string]any)
	if reportMap == nil || reportMap["mode"] != "custom" {
		t.Errorf("unexpected scan report payload: %+v", scanData)
	}

	// 4. Verify /api/admin/firewall/status and strict input validation on /api/admin/firewall/*
	fwReq, _ := http.NewRequest("GET", ts.URL+"/api/admin/firewall/status", nil)
	fwReq.AddCookie(cookie)
	fwRes, err := http.DefaultClient.Do(fwReq)
	if err != nil || fwRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/admin/firewall/status failed: err=%v status=%v", err, fwRes)
	}
	var fwStatusBody map[string]any
	rawFW, _ := io.ReadAll(fwRes.Body)
	fwRes.Body.Close()
	if err := json.Unmarshal(rawFW, &fwStatusBody); err != nil || fwStatusBody["ok"] != true {
		t.Fatalf("invalid firewall status JSON: %v (%s)", err, string(rawFW))
	}
	fwObj, _ := fwStatusBody["firewall"].(map[string]any)
	if fwObj == nil || int(fwObj["reality_port"].(float64)) != 28443 {
		t.Errorf("expected firewall status to reflect RealityPort=28443, got %+v", fwObj)
	}

	// Reject invalid firewall rule spec before invoking ufw
	respBadRule, badRuleData := doAdminPost("/api/admin/firewall/rule/add", map[string]any{
		"action": "allow",
		"port":   "10000:20000",
		"proto":  "any", // range without tcp/udp must fail validation
	})
	if respBadRule.StatusCode != http.StatusBadRequest || badRuleData["ok"] != false {
		t.Errorf("expected 400 for invalid range proto=any, got status=%d data=%+v", respBadRule.StatusCode, badRuleData)
	}

	// Reject unknown firewall action
	respBadAct, _ := doAdminPost("/api/admin/firewall/action", map[string]any{
		"action": "flush_all_chains",
	})
	if respBadAct.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported firewall action, got %d", respBadAct.StatusCode)
	}
}
