package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kokmmm33/newsuoha.sh/panel/internal/config"
)

const (
	sessionCookieName = "suoha_sid"
	sessionTTL        = 7 * 24 * time.Hour
	maxLoginFailures  = 5
	lockoutWindow     = 5 * time.Minute
)

type sessionRecord struct {
	username  string
	expiresAt time.Time
}

// SessionManager manages authenticated admin sessions in memory.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]sessionRecord
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]sessionRecord),
	}
}

func (sm *SessionManager) Create(username string) string {
	sid := config.RandomHex(32)
	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Evict expired sessions and cap total entries
	for k, v := range sm.sessions {
		if now.After(v.expiresAt) {
			delete(sm.sessions, k)
		}
	}
	if len(sm.sessions) >= 64 {
		for k := range sm.sessions {
			delete(sm.sessions, k)
			break
		}
	}
	sm.sessions[sid] = sessionRecord{
		username:  username,
		expiresAt: now.Add(sessionTTL),
	}
	return sid
}

func (sm *SessionManager) Validate(r *http.Request) (string, bool) {
	sid := extractSessionToken(r)
	if sid == "" {
		return "", false
	}

	now := time.Now()
	sm.mu.Lock()
	defer sm.mu.Unlock()

	rec, ok := sm.sessions[sid]
	if !ok {
		return "", false
	}
	if now.After(rec.expiresAt) {
		delete(sm.sessions, sid)
		return "", false
	}
	// Sliding expiration
	rec.expiresAt = now.Add(sessionTTL)
	sm.sessions[sid] = rec
	return rec.username, true
}

func (sm *SessionManager) DeleteRequestSession(r *http.Request) {
	sid := extractSessionToken(r)
	if sid == "" {
		return
	}
	sm.mu.Lock()
	delete(sm.sessions, sid)
	sm.mu.Unlock()
}

func (sm *SessionManager) ClearAll() {
	sm.mu.Lock()
	sm.sessions = make(map[string]sessionRecord)
	sm.mu.Unlock()
}

func extractSessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

type failRecord struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// LoginLimiter protects the root login endpoint against brute-force password guessing.
type LoginLimiter struct {
	mu      sync.Mutex
	records map[string]failRecord
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		records: make(map[string]failRecord),
	}
}

func (l *LoginLimiter) CheckAllowed(ip string) (bool, string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	rec, ok := l.records[ip]
	if !ok {
		return true, ""
	}
	if now.Before(rec.lockedUntil) {
		rem := int(rec.lockedUntil.Sub(now).Seconds()) + 1
		return false, fmt.Sprintf("登录失败次数过多，请 %d 秒后再试", rem)
	}
	if now.Sub(rec.windowStart) > lockoutWindow {
		delete(l.records, ip)
	}
	return true, ""
}

func (l *LoginLimiter) RecordFailure(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Opportunistic cleanup
	if len(l.records) > 1024 {
		for k, v := range l.records {
			if now.After(v.lockedUntil) && now.Sub(v.windowStart) > lockoutWindow {
				delete(l.records, k)
			}
		}
	}

	rec, ok := l.records[ip]
	if !ok || now.Sub(rec.windowStart) > lockoutWindow {
		rec = failRecord{
			count:       1,
			windowStart: now,
		}
	} else {
		rec.count++
		if rec.count >= maxLoginFailures {
			rec.lockedUntil = now.Add(lockoutWindow)
		}
	}
	l.records[ip] = rec
}

func (l *LoginLimiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.records, ip)
	l.mu.Unlock()
}

func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if cfIP := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); cfIP != "" {
			return cfIP
		}
	}
	return host
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
