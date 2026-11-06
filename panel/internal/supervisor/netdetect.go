package supervisor

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// NetworkInfo holds detected public IPv4, public IPv6, and ISP/region tag.
type NetworkInfo struct {
	ServerIP string `json:"server_ip"`
	IPv6Addr string `json:"ipv6_addr"`
	NodeTag  string `json:"node_tag"`
}

// DetectNetwork probes outbound public IPv4, IPv6, and Cloudflare colo/country tag with fast timeouts.
func DetectNetwork() NetworkInfo {
	v4 := DetectPublicIPv4()
	v6 := DetectPublicIPv6()
	serverIP := v4
	if serverIP == "" {
		serverIP = v6
	}
	if serverIP == "" {
		serverIP = detectOutboundLocalIP()
	}
	tag := DetectNodeTag()
	return NetworkInfo{
		ServerIP: serverIP,
		IPv6Addr: v6,
		NodeTag:  tag,
	}
}

// DetectPublicIPv4 returns the machine's public IPv4 address if reachable.
func DetectPublicIPv4() string {
	endpoints := []string{
		"https://www.cloudflare.com/cdn-cgi/trace",
		"https://ipv4.icanhazip.com",
		"https://api.ip.sb/ip",
	}
	client := newFamilyHTTPClient("tcp4", 2500*time.Millisecond)
	for _, u := range endpoints {
		body := fetchBody(client, u)
		if body == "" {
			continue
		}
		if strings.Contains(u, "cdn-cgi/trace") {
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "ip=") {
					cand := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
					if ip := net.ParseIP(cand); ip != nil && ip.To4() != nil {
						return ip.String()
					}
				}
			}
			continue
		}
		cand := strings.TrimSpace(body)
		if ip := net.ParseIP(cand); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// DetectPublicIPv6 returns the machine's public global IPv6 address if available.
func DetectPublicIPv6() string {
	endpoints := []string{
		"https://www.cloudflare.com/cdn-cgi/trace",
		"https://ipv6.icanhazip.com",
		"https://api64.ipify.org",
	}
	client := newFamilyHTTPClient("tcp6", 2500*time.Millisecond)
	for _, u := range endpoints {
		body := fetchBody(client, u)
		if body == "" {
			continue
		}
		if strings.Contains(u, "cdn-cgi/trace") {
			for _, line := range strings.Split(body, "\n") {
				if strings.HasPrefix(line, "ip=") {
					cand := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
					if ip := net.ParseIP(cand); ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
						return ip.String()
					}
				}
			}
			continue
		}
		cand := strings.TrimSpace(body)
		if ip := net.ParseIP(cand); ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
			return ip.String()
		}
	}

	// Fallback: inspect global non-private IPv6 interface addresses
	ifaces, err := net.InterfaceAddrs()
	if err == nil {
		for _, a := range ifaces {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			ip := ipNet.IP
			if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
				return ip.String()
			}
		}
	}
	return ""
}

// DetectNodeTag fetches country/colo metadata from Cloudflare speed meta or trace.
func DetectNodeTag() string {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	if body := fetchBody(client, "https://speed.cloudflare.com/meta"); body != "" {
		var meta struct {
			Country string `json:"country"`
			Colo    string `json:"colo"`
			AsOrg   string `json:"asOrganization"`
		}
		if json.Unmarshal([]byte(body), &meta) == nil && (meta.Country != "" || meta.Colo != "") {
			parts := []string{}
			if meta.Country != "" {
				parts = append(parts, meta.Country)
			}
			if meta.Colo != "" {
				parts = append(parts, meta.Colo)
			}
			if len(parts) > 0 {
				return strings.Join(parts, "-")
			}
		}
	}
	if body := fetchBody(client, "https://www.cloudflare.com/cdn-cgi/trace"); body != "" {
		var loc, colo string
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(line, "loc=") {
				loc = strings.TrimSpace(strings.TrimPrefix(line, "loc="))
			} else if strings.HasPrefix(line, "colo=") {
				colo = strings.TrimSpace(strings.TrimPrefix(line, "colo="))
			}
		}
		if loc != "" && colo != "" {
			return loc + "-" + colo
		}
	}
	return "Argo_Node"
}

func detectOutboundLocalIP() string {
	conn, err := net.DialTimeout("udp", "1.1.1.1:80", 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}

func newFamilyHTTPClient(network string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

func fetchBody(client *http.Client, u string) string {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "suoha-panel/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	return string(b)
}
