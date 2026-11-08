package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

func writeMockExecutable(t *testing.T, path, scriptBody string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	// Ensure size >= 1024 bytes so supervisor.isExecutableFile accepts the mock binary without downloading
	padding := "\n# " + strings.Repeat("suoha-mock-binary-padding-", 60) + "\n"
	content := "#!/usr/bin/env bash\nset -e\n" + scriptBody + padding
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write mock %s: %v", path, err)
	}
}

func TestBuildNamedTunnelNameAndYAML(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"sub.example.com", "suoha-sub-example-com"},
		{"HTTPS://Node-01.Sub.Example.COM:443/path", "suoha-node-01-sub-example-com"},
		{"", "suoha-node"},
	}
	for _, tc := range cases {
		got := config.BuildNamedTunnelName(tc.in)
		if got != tc.want {
			t.Errorf("BuildNamedTunnelName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	veryLong := strings.Repeat("abcdefghij.", 8) + "example.com"
	longSlug := config.BuildNamedTunnelName(veryLong)
	if len(longSlug) > 54 || strings.HasSuffix(longSlug, "-") {
		t.Errorf("expected truncated slug <= 54 chars without trailing dash, got %q (len=%d)", longSlug, len(longSlug))
	}

	yamlOut := supervisor.BuildNamedTunnelConfigYAML(
		"11111111-2222-3333-4444-555555555555",
		"/opt/suoha/cloudflared/11111111-2222-3333-4444-555555555555.json",
		"sub.example.com",
		28080,
	)
	for _, frag := range []string{
		"tunnel: '11111111-2222-3333-4444-555555555555'",
		"credentials-file: '/opt/suoha/cloudflared/11111111-2222-3333-4444-555555555555.json'",
		"hostname: 'sub.example.com'",
		"service: http://127.0.0.1:28080",
		"service: http_status:404",
	} {
		if !strings.Contains(yamlOut, frag) {
			t.Errorf("YAML missing %q:\n%s", frag, yamlOut)
		}
	}
}

func TestOAuthLifecycleAndLegacyCertImport(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	legacyDir := filepath.Join(tmp, "legacy_cf")
	_ = os.MkdirAll(legacyDir, 0700)

	store, err := config.LoadOrInit(dataDir, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	initPwd := store.InitialGeneratedPassword()
	logs := supervisor.NewRingLog(100)
	mgr := supervisor.NewManager(store, logs, nil)
	mgr.SetLegacyCloudflaredDirs([]string{legacyDir})
	defer mgr.Shutdown()

	// 1. Initially unauthorized
	if st := mgr.OAuthStatus(); st.Authorized {
		t.Fatalf("expected initial Authorized=false, got %+v", st)
	}

	// 2. Legacy cert.pem is automatically imported into <dataDir>/cloudflared/cert.pem
	legacyCertContent := "-----BEGIN ARGO TUNNEL TOKEN-----\nLEGACY-CERT-PAYLOAD-1234567890\n-----END ARGO TUNNEL TOKEN-----\n"
	if err := os.WriteFile(filepath.Join(legacyDir, "cert.pem"), []byte(legacyCertContent), 0600); err != nil {
		t.Fatal(err)
	}
	if st := mgr.OAuthStatus(); !st.Authorized || st.CertPath != supervisor.OriginCertPath(dataDir) {
		t.Fatalf("expected legacy cert.pem auto-import, got %+v", st)
	}

	// 3. Test Web OAuth Start + Cancel preserves existing cert.pem, then Start + Complete updates cert.pem
	modeFlagFile := filepath.Join(tmp, "oauth_mode.txt")
	_ = os.WriteFile(modeFlagFile, []byte("hang"), 0644)

	cfScript := fmt.Sprintf(`
MODE=$(cat %q)
for arg in "$@"; do
  if [ "$arg" = "login" ]; then
    echo "Please open the following URL and log in with your Cloudflare account:" >&2
    echo "https://dash.cloudflare.com/argotunnel?aud=mock-session-xyz" >&2
    if [ "$MODE" = "hang" ]; then
      sleep 30
      exit 1
    fi
    sleep 0.15
    mkdir -p "$HOME/.cloudflared"
    cat > "$HOME/.cloudflared/cert.pem" <<'EOF'
-----BEGIN ARGO TUNNEL TOKEN-----
FRESH-BROWSER-OAUTH-CERT-9876543210
-----END ARGO TUNNEL TOKEN-----
EOF
    exit 0
  fi
done
exit 0
`, modeFlagFile)
	writeMockExecutable(t, filepath.Join(dataDir, "bin", "cloudflared"), cfScript)

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
		t.Fatalf("login failed: %v", err)
	}
	cookie := loginRes.Cookies()[0]
	loginRes.Body.Close()

	doAdmin := func(method, path, body string) map[string]any {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s %s HTTP %d: %+v", method, path, resp.StatusCode, out)
		}
		return out
	}

	// Start hanging re-auth session -> returns waiting + auth_url
	startOut := doAdmin("POST", "/api/admin/tunnel/oauth/start", `{"edge_ip_version":"4"}`)
	oauthMap, _ := startOut["oauth"].(map[string]any)
	if oauthMap["state"] != "waiting" || !strings.Contains(fmt.Sprint(oauthMap["auth_url"]), "https://dash.cloudflare.com/argotunnel") {
		t.Fatalf("expected waiting OAuth state with URL, got %+v", oauthMap)
	}

	// Cancel re-auth -> existing legacy cert.pem MUST still be intact!
	cancelOut := doAdmin("POST", "/api/admin/tunnel/oauth/cancel", `{}`)
	cancelOAuth, _ := cancelOut["oauth"].(map[string]any)
	if cancelOAuth["authorized"] != true {
		t.Fatalf("expected existing cert.pem to remain authorized after cancel, got %+v", cancelOAuth)
	}
	savedRaw, _ := os.ReadFile(supervisor.OriginCertPath(dataDir))
	if !bytes.Contains(savedRaw, []byte("LEGACY-CERT-PAYLOAD")) {
		t.Fatalf("expected original cert.pem content preserved after cancel, got %s", string(savedRaw))
	}

	// Switch mock to complete OAuth -> cert.pem replaced with fresh browser cert
	_ = os.WriteFile(modeFlagFile, []byte("complete"), 0644)
	_ = doAdmin("POST", "/api/admin/tunnel/oauth/start", `{"edge_ip_version":"4"}`)

	deadline := time.Now().Add(4 * time.Second)
	completed := false
	for time.Now().Before(deadline) {
		stOut := doAdmin("GET", "/api/admin/tunnel/oauth/status", "")
		om, _ := stOut["oauth"].(map[string]any)
		if om["state"] == "succeeded" {
			completed = true
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	if !completed {
		t.Fatalf("timed out waiting for OAuth session to reach succeeded state")
	}
	updatedRaw, _ := os.ReadFile(supervisor.OriginCertPath(dataDir))
	if !bytes.Contains(updatedRaw, []byte("FRESH-BROWSER-OAUTH-CERT")) {
		t.Fatalf("expected newly authorized cert.pem to be written, got %s", string(updatedRaw))
	}
}

func TestNamedTunnelEndToEndRecoveryAndConflictWithoutDelete(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")

	store, err := config.LoadOrInit(dataDir, config.LegacyPaths{}, false)
	if err != nil {
		t.Fatal(err)
	}
	initPwd := store.InitialGeneratedPassword()
	logs := supervisor.NewRingLog(200)
	mgr := supervisor.NewManager(store, logs, nil)
	mgr.SetLegacyCloudflaredDirs(nil)
	defer mgr.Shutdown()

	// Pre-seed valid cert.pem
	certPath := supervisor.OriginCertPath(dataDir)
	_ = os.MkdirAll(filepath.Dir(certPath), 0700)
	_ = os.WriteFile(certPath, []byte("-----BEGIN ARGO TUNNEL TOKEN-----\nMOCK-ORIGIN-CERT-DATA-123456\n-----END ARGO TUNNEL TOKEN-----\n"), 0600)

	invLog := filepath.Join(tmp, "cf_invocations.log")
	recoverTok := base64.StdEncoding.EncodeToString([]byte(`{"a":"acct-recover","t":"22222222-3333-4444-5555-666666666666","s":"sec-recover"}`))

	// Mock xray binary (sleeps quietly while supervised)
	writeMockExecutable(t, filepath.Join(dataDir, "bin", "xray"), `sleep 30`)

	// Mock cloudflared binary supporting list, create, token recovery, route dns, and run
	cfScript := fmt.Sprintf(`
echo "$*" >> %q
CMD=""
PREV=""
CRED_FILE=""
LAST_ARG=""
for a in "$@"; do
  if [ "$PREV" = "--cred-file" ]; then
    CRED_FILE="$a"
  fi
  case "$a" in
    list|create|token|route|run|delete)
      if [ -z "$CMD" ]; then CMD="$a"; fi
      ;;
  esac
  PREV="$a"
  LAST_ARG="$a"
done

if [ "$CMD" = "delete" ]; then
  echo "FATAL: tunnel delete must never be called!" >&2
  exit 99
fi

if [ "$CMD" = "list" ]; then
  cat <<'EOF'
[
  {"id":"22222222-3333-4444-5555-666666666666","name":"suoha-reinstall-example-com","deleted_at":"0001-01-01T00:00:00Z"},
  {"id":"99999999-8888-7777-6666-555555555555","name":"suoha-conflict-example-com","deleted_at":"0001-01-01T00:00:00Z"}
]
EOF
  exit 0
fi

if [ "$CMD" = "token" ]; then
  if [ "$LAST_ARG" = "22222222-3333-4444-5555-666666666666" ]; then
    echo %q
    exit 0
  fi
  echo "cannot fetch token for tunnel" >&2
  exit 1
fi

if [ "$CMD" = "create" ]; then
  if [ "$LAST_ARG" = "suoha-sub-example-com" ]; then
    UUID="11111111-aaaa-bbbb-cccc-dddddddddddd"
  else
    UUID="33333333-aaaa-bbbb-cccc-eeeeeeeeeeee"
  fi
  if [ -n "$CRED_FILE" ]; then
    printf '{"AccountTag":"acct-new","TunnelID":"%%s","TunnelSecret":"sec-new"}\n' "$UUID" > "$CRED_FILE"
  fi
  echo "Created tunnel $LAST_ARG with id $UUID"
  exit 0
fi

if [ "$CMD" = "route" ]; then
  echo "Added CNAME $LAST_ARG which will route to this tunnel"
  exit 0
fi

if [ "$CMD" = "run" ]; then
  echo "INF Registered tunnel connection connIndex=0"
  sleep 30
  exit 0
fi
exit 0
`, invLog, recoverTok)
	writeMockExecutable(t, filepath.Join(dataDir, "bin", "cloudflared"), cfScript)

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
		t.Fatalf("login failed: %v", err)
	}
	cookie := loginRes.Cookies()[0]
	loginRes.Body.Close()

	// Case A: End-to-end POST /api/admin/tunnel/apply in "named" mode for sub.example.com
	applyBody := `{"enabled":true,"mode":"named","edge_ip_version":"4","custom_domain":"sub.example.com"}`
	applyReq, _ := http.NewRequest("POST", ts.URL+"/api/admin/tunnel/apply", strings.NewReader(applyBody))
	applyReq.AddCookie(cookie)
	applyReq.Header.Set("Content-Type", "application/json")
	applyRes, err := http.DefaultClient.Do(applyReq)
	if err != nil {
		t.Fatal(err)
	}
	var applyOut map[string]any
	_ = json.NewDecoder(applyRes.Body).Decode(&applyOut)
	applyRes.Body.Close()
	if applyRes.StatusCode != http.StatusOK || applyOut["ok"] != true {
		t.Fatalf("POST /api/admin/tunnel/apply failed (%d): %+v", applyRes.StatusCode, applyOut)
	}
	if applyOut["tunnel_name"] != "suoha-sub-example-com" || applyOut["tunnel_uuid"] != "11111111-aaaa-bbbb-cccc-dddddddddddd" {
		t.Errorf("unexpected created tunnel metadata: %+v", applyOut)
	}

	// Verify isolated YAML config was written and subscription reflects sub.example.com
	yamlBytes, err := os.ReadFile(supervisor.NamedTunnelConfigPath(dataDir))
	if err != nil {
		t.Fatalf("expected runtime/cloudflared_named.yaml to exist: %v", err)
	}
	if !strings.Contains(string(yamlBytes), "hostname: 'sub.example.com'") {
		t.Errorf("unexpected cloudflared_named.yaml content:\n%s", string(yamlBytes))
	}

	ovReq, _ := http.NewRequest("GET", ts.URL+"/api/admin/overview", nil)
	ovReq.AddCookie(cookie)
	ovRes, err := http.DefaultClient.Do(ovReq)
	if err != nil || ovRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/admin/overview failed: %v", err)
	}
	var ov map[string]any
	_ = json.NewDecoder(ovRes.Body).Decode(&ov)
	ovRes.Body.Close()
	subMap, _ := ov["subscription"].(map[string]any)
	if !strings.HasPrefix(fmt.Sprint(subMap["argo_sub_url"]), "https://sub.example.com/") {
		t.Errorf("expected https://sub.example.com/ argo_sub_url, got %v", subMap["argo_sub_url"])
	}

	// Case B: Non-destructive credential recovery when tunnel already exists on Cloudflare (OS reinstall scenario)
	recRes, err := supervisor.ProvisionNamedTunnelWithStore(
		context.Background(),
		dataDir,
		nil,
		logs,
		"reinstall.example.com",
		"4",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("expected credential recovery to succeed, got error: %v", err)
	}
	if !recRes.Reused || recRes.TunnelName != "suoha-reinstall-example-com" || recRes.TunnelUUID != "22222222-3333-4444-5555-666666666666" {
		t.Errorf("unexpected recovered tunnel result: %+v", recRes)
	}

	// Case C: Non-destructive suffixed fallback when existing cloud tunnel credentials cannot be recovered
	confRes, err := supervisor.ProvisionNamedTunnelWithStore(
		context.Background(),
		dataDir,
		nil,
		logs,
		"conflict.example.com",
		"4",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("expected suffixed tunnel fallback to succeed, got error: %v", err)
	}
	if !strings.HasPrefix(confRes.TunnelName, "suoha-conflict-example-com-") || confRes.TunnelUUID != "33333333-aaaa-bbbb-cccc-eeeeeeeeeeee" {
		t.Errorf("expected suffixed tunnel name, got %+v", confRes)
	}

	// Subsequent provision with persisted suffixed name reuses it idempotently
	confReuse, err := supervisor.ProvisionNamedTunnelWithStore(
		context.Background(),
		dataDir,
		nil,
		logs,
		"conflict.example.com",
		"4",
		confRes.TunnelName,
		confRes.TunnelUUID,
	)
	if err != nil || !confReuse.Reused || confReuse.TunnelName != confRes.TunnelName {
		t.Fatalf("expected suffixed tunnel to be reused idempotently, got %+v (err=%v)", confReuse, err)
	}

	// Verify `tunnel delete` was NEVER invoked anywhere, and `--overwrite-dns` was passed to `route dns`
	invRaw, err := os.ReadFile(invLog)
	if err != nil {
		t.Fatal(err)
	}
	invText := string(invRaw)
	if strings.Contains(invText, " delete ") || strings.HasSuffix(invText, " delete\n") {
		t.Fatalf("cloudflared tunnel delete MUST NEVER be invoked! Log:\n%s", invText)
	}
	if !strings.Contains(invText, "tunnel route dns --overwrite-dns 11111111-aaaa-bbbb-cccc-dddddddddddd sub.example.com") {
		t.Errorf("expected route dns --overwrite-dns invocation in log:\n%s", invText)
	}
}
