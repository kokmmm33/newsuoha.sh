package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

// WSDispatcher inspects incoming request paths and forwards matching VLESS/Trojan WebSocket traffic to local Xray.
type WSDispatcher struct {
	store *config.Store
}

func NewWSDispatcher(store *config.Store) *WSDispatcher {
	return &WSDispatcher{store: store}
}

// TryServe proxies the request to local Xray if reqPath matches an enabled VLESS or Trojan WebSocket path.
// Returns true if the request was matched and handled.
func (d *WSDispatcher) TryServe(w http.ResponseWriter, r *http.Request) bool {
	cfg := d.store.GetConfig()
	proto := cfg.Protocols
	cleanPath := strings.TrimPrefix(r.URL.Path, "/")

	var targetPort int
	if proto.VLESSEnabled && proto.VLESSPath != "" && (cleanPath == proto.VLESSPath || strings.HasPrefix(cleanPath, proto.VLESSPath+"/")) {
		targetPort = proto.VLESSLocalPort
	} else if proto.TrojanEnabled && proto.TrojanPath != "" && (cleanPath == proto.TrojanPath || strings.HasPrefix(cleanPath, proto.TrojanPath+"/")) {
		targetPort = proto.TrojanLocalPort
	} else {
		return false
	}

	targetURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", targetPort))
	if err != nil {
		http.Error(w, "Bad gateway target", http.StatusBadGateway)
		return true
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host
		},
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
			rw.WriteHeader(http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	return true
}
