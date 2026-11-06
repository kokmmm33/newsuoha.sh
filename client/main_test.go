package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAPIURL(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:28000":                       "http://1.2.3.4:28000/api/update_ips",
		"http://1.2.3.4:28000/":               "http://1.2.3.4:28000/api/update_ips",
		"http://1.2.3.4:28000/sub.txt":        "http://1.2.3.4:28000/api/update_ips",
		"http://1.2.3.4:28000/clash.yaml":     "http://1.2.3.4:28000/api/update_ips",
		"http://1.2.3.4:28000/api/update_ips": "http://1.2.3.4:28000/api/update_ips",
	}
	for in, want := range cases {
		if got := normalizeAPIURL(in); got != want {
			t.Errorf("normalizeAPIURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildDirectEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://127.0.0.1:7890",
		"https_proxy=http://127.0.0.1:7890",
		"ALL_PROXY=socks5://127.0.0.1:7891",
		"HOME=/home/user",
	}
	got := buildDirectEnv(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 env vars remaining, got %v", got)
	}
}

func TestParseResultCSV(t *testing.T) {
	tmpDir := t.TempDir()
	csvFile := filepath.Join(tmpDir, "result.csv")
	csvContent := "\xef\xbb\xbfIP 地址,已发送,已接收,丢包率,平均延迟,下载速度 (MB/s),地区码\n" +
		"104.16.10.1,4,4,0.00,36.42,21.58,HKG\n" +
		"104.16.10.2,4,4,0.00,48.10,14.20,SJC\n" +
		"104.16.10.3,4,1,0.75,55.00,10.00,LAX\n"
	if err := os.WriteFile(csvFile, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	ips, err := parseResultCSV(csvFile, 5, 443, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 valid IPs (1 filtered by high loss), got %d", len(ips))
	}
	if ips[0].IP != "104.16.10.1" || ips[0].Label != "优选1-HKG-36ms-21.6MB" {
		t.Errorf("unexpected first IP entry: %+v", ips[0])
	}
	if ips[1].IP != "104.16.10.2" || ips[1].Label != "优选2-SJC-48ms-14.2MB" {
		t.Errorf("unexpected second IP entry: %+v", ips[1])
	}
}

func TestUploadPreferredIPs(t *testing.T) {
	var received UploadPayload
	var authHdr string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"count":1,"updated_at":"2026-11-05 16:00:00","regenerated":true}`))
	}))
	defer srv.Close()

	ips := []PreferredIP{
		{IP: "104.16.1.1", Port: 443, Latency: "35ms", Speed: "20.0MB", Label: "优选1-35ms-20.0MB"},
	}
	if err := uploadPreferredIPs(srv.URL+"/api/update_ips", "secrettoken", ips); err != nil {
		t.Fatalf("uploadPreferredIPs failed: %v", err)
	}
	if authHdr != "Bearer secrettoken" {
		t.Errorf("expected Bearer secrettoken, got %q", authHdr)
	}
	if len(received.IPs) != 1 || received.IPs[0].IP != "104.16.1.1" {
		t.Errorf("unexpected payload received: %+v", received)
	}
}
