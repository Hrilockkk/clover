package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"scanner/internal/embedded"
	"scanner/internal/logger"
	"scanner/internal/models"
	"scanner/internal/obfuscate"
	"scanner/internal/ratelimit"
)

// ─── Config types ──────────────────────────────────────────────────────────

type AdminUser struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`       // legacy plaintext, prefer hash
	PasswordHash string `json:"passwordHash,omitempty"` // bcrypt hash
}

type ServerConfig struct {
	SecretKey string      `json:"secretKey"`
	Admins    []AdminUser `json:"admins"`
}

func loadConfig() *ServerConfig {
	cfg := &ServerConfig{
		SecretKey: genRandomHex(32),
		Admins:    []AdminUser{},
	}
	data, err := os.ReadFile("admins.json")
	if err == nil {
		if uerr := json.Unmarshal(data, cfg); uerr != nil {
			logger.Error("failed to parse admins.json, using empty config", "error", uerr)
		}
		return cfg
	}
	if !os.IsNotExist(err) {
		logger.Error("failed to read admins.json", "error", err)
	}
	// Create a fresh config file with no default admin password.
	data, merr := json.MarshalIndent(cfg, "", "  ")
	if merr == nil {
		if werr := os.WriteFile("admins.json", data, 0600); werr != nil {
			logger.Error("failed to write admins.json", "error", werr)
		}
	}
	return cfg
}

var srvCfg *ServerConfig

// ─── Data types ────────────────────────────────────────────────────────────

type ScanLink struct {
	ID             string `json:"id"`
	CreatedAt      string `json:"createdAt"`
	Note           string `json:"note"`
	AdminUser      string `json:"adminUser"`
	PlayerPassword string `json:"playerPassword"`
}

type ScanRecord struct {
	ScanID       string                   `json:"scanId"`
	LinkID       string                   `json:"linkId"`
	AdminUser    string                   `json:"adminUser"`
	Timestamp    string                   `json:"timestamp"`
	Hardware     *models.HardwareInfo     `json:"hardware"`
	Steam        *models.SteamInfo       `json:"steam"`
	Results      []models.FileInfo        `json:"results"`
	Dirs         []models.DirInfo         `json:"dirs"`
	NamedFiles   []models.NamedFileInfo   `json:"namedFiles"`
	DeletedFiles []models.DeletedFileInfo `json:"deletedFiles"`
	DeletedDirs  []models.DeletedDirInfo  `json:"deletedDirs"`
	Shellbags    []models.ShellbagFinding `json:"shellbags"`
	AppData      []models.AppDataFinding  `json:"appData"`
	Amcache      []models.AmcacheFinding  `json:"amcache"`
	CS2Conns     []models.CS2Connection   `json:"cs2Conns"`
	CS2RWX       []models.CS2RWXRegion    `json:"cs2Rwx"`
	Prefetch     []models.PrefetchEntry   `json:"prefetch"`
	Shimcache    []models.ShimcacheEntry  `json:"shimcache"`
	Bam          []models.BamEntry        `json:"bam"`
	Processes    []models.ProcessEntry    `json:"processes"`
	Drivers      []models.DriverEntry     `json:"drivers"`
	ShellbagsAll []models.ShellbagEntry   `json:"shellbagsAll"`
	Services     []models.ServiceEntry    `json:"services"`
	Cleanup      *models.CleanupInfo      `json:"cleanup,omitempty"`
	USN          []models.UsnEntry        `json:"usn,omitempty"`
	Elapsed      float64                  `json:"elapsedSeconds"`
}

// EmbeddedConfig is the JSON blob appended to scanner.exe for per-link customization.
type EmbeddedConfig struct {
	ScanID         string `json:"scanId"`
	UploadURL      string `json:"uploadUrl"`
	PlayerPassword string `json:"playerPassword"`
}

var configMarker = obfuscate.CONFIG_MARKER()

// ─── Storage ──────────────────────────────────────────────────────────────

var (
	dataDir  = "data"
	linksDir = filepath.Join(dataDir, "links")
	scansDir = filepath.Join(dataDir, "scans")
	storeMu  sync.Mutex
)

func initStorage() {
	os.MkdirAll(linksDir, 0755)
	os.MkdirAll(scansDir, 0755)
}

func isSafeID(id string) bool {
	if len(id) < 16 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func linkPath(id string) string {
	return filepath.Join(linksDir, id+".json")
}

func scanPath(id string) string {
	return filepath.Join(scansDir, id+".json")
}

func genID() string {
	return genRandomHex(16)
}

func genRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n*2]
	}
	return hex.EncodeToString(b)
}

func saveLink(link *ScanLink) error {
	data, err := json.MarshalIndent(link, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(linkPath(link.ID), data, 0644)
}

func loadLink(id string) (*ScanLink, error) {
	data, err := os.ReadFile(linkPath(id))
	if err != nil {
		return nil, err
	}
	var link ScanLink
	if err := json.Unmarshal(data, &link); err != nil {
		return nil, err
	}
	return &link, nil
}

func loadLinks() []ScanLink {
	entries, err := os.ReadDir(linksDir)
	if err != nil {
		return nil
	}
	var links []ScanLink
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(linksDir, e.Name()))
		if err != nil {
			continue
		}
		var link ScanLink
		if json.Unmarshal(data, &link) == nil {
			links = append(links, link)
		}
	}
	sort.Slice(links, func(i, j int) bool {
		return links[i].CreatedAt > links[j].CreatedAt
	})
	return links
}

func saveScan(rec *ScanRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(scanPath(rec.ScanID), data, 0644)
}

func loadScan(id string) (*ScanRecord, error) {
	data, err := os.ReadFile(scanPath(id))
	if err != nil {
		return nil, err
	}
	var rec ScanRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func loadAllScans() []ScanRecord {
	entries, err := os.ReadDir(scansDir)
	if err != nil {
		return nil
	}
	var records []ScanRecord
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(scansDir, e.Name()))
		if err != nil {
			continue
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) == nil {
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp > records[j].Timestamp
	})
	return records
}

// ─── Session management ────────────────────────────────────────────────────

type Session struct {
	Username  string
	ExpiresAt time.Time
}

var (
	sessions   = make(map[string]*Session)
	sessionsMu sync.Mutex
)

func createSession(username string) string {
	sid := genRandomHex(32)
	sessionsMu.Lock()
	sessions[sid] = &Session{
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionsMu.Unlock()
	return sid
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("clover_session")
	if err != nil {
		return nil
	}
	sessionsMu.Lock()
	s, ok := sessions[cookie.Value]
	sessionsMu.Unlock()
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil
	}
	return s
}

func sessionCookie(value string, secure bool) *http.Cookie {
	return &http.Cookie{
		Name:     "clover_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
		MaxAge:   86400,
	}
}

func setupRequired() bool {
	return len(srvCfg.Admins) == 0
}

// requireAuth requires a valid session. If the server is not set up yet,
// it redirects to /setup.
func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupRequired() {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		s := getSession(r)
		if s == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		handler(w, r)
	}
}

// withSetup redirects unauthenticated first-time visitors to the setup page.
func withSetup(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupRequired() && r.URL.Path != "/setup" {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		handler(w, r)
	}
}

// ─── Rate limiters ─────────────────────────────────────────────────────────

var (
	loginLimiter  = ratelimit.New(12*time.Second, 10, 10*time.Minute) // 5/min burst 10
	uploadLimiter = ratelimit.New(3*time.Second, 50, 10*time.Minute)  // 20/min burst 50
)

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}

// ─── HTTP handlers ─────────────────────────────────────────────────────────

func handleSetup(w http.ResponseWriter, r *http.Request) {
	if !setupRequired() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == "GET" {
		renderSetup(w, "")
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderSetup(w, "Invalid form")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if username == "" || password == "" {
		renderSetup(w, "Username and password are required")
		return
	}
	if len(password) < 12 {
		renderSetup(w, "Password must be at least 12 characters")
		return
	}
	if password != confirm {
		renderSetup(w, "Passwords do not match")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderSetup(w, "Failed to hash password")
		return
	}
	srvCfg.Admins = []AdminUser{{Username: username, PasswordHash: string(hash)}}
	if err := saveServerConfig(); err != nil {
		srvCfg.Admins = nil
		renderSetup(w, "Failed to save config")
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func saveServerConfig() error {
	data, err := json.MarshalIndent(srvCfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("admins.json", data, 0600)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if setupRequired() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.Method == "GET" {
		renderLogin(w, "")
		return
	}
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !loginLimiter.Allow(clientIP(r)) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderLogin(w, "Invalid form")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	for _, a := range srvCfg.Admins {
		if a.Username != username {
			continue
		}
		ok := false
		if a.PasswordHash != "" {
			ok = bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte(password)) == nil
		} else if a.Password != "" {
			ok = a.Password == password
		}
		if ok {
			sid := createSession(username)
			http.SetCookie(w, sessionCookie(sid, r.TLS != nil))
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}
	renderLogin(w, "Invalid credentials")
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("clover_session")
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "clover_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s := getSession(r)
	links := loadLinks()
	scans := loadAllScans()
	renderIndex(w, s.Username, links, scans)
}

func handleCreateLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s := getSession(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req struct {
		Note     string `json:"note"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "json parse: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Note) > 256 {
		req.Note = req.Note[:256]
	}
	if len(req.Password) > 128 {
		req.Password = req.Password[:128]
	}

	link := &ScanLink{
		ID:             genID(),
		CreatedAt:      time.Now().Format("2006-01-02 15:04:05"),
		Note:           req.Note,
		AdminUser:      s.Username,
		PlayerPassword: req.Password,
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if err := saveLink(link); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(map[string]string{
		"id":  link.ID,
		"url": "/s/" + link.ID,
	})
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/s/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	link, err := loadLink(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderScanPage(w, link)
}

func handleScanUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !uploadLimiter.Allow(clientIP(r)) {
		http.Error(w, "too many uploads", http.StatusTooManyRequests)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/scans/upload/")
	if id == r.URL.Path {
		id = strings.TrimPrefix(r.URL.Path, "/api/scan/")
	}
	id = strings.TrimSuffix(id, "/")

	const maxUploadBytes = 8 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		}
		return
	}

	// The scanner may upload either a plain JSON body or an encrypted envelope.
	if encBody, ok := extractEncryptedEnvelope(body); ok {
		plain, err := embedded.DecryptPayloadBase64(string(encBody))
		if err != nil {
			logger.Warn("upload decrypt failed", "error", err, "scanId", id)
			http.Error(w, "decrypt failed", http.StatusForbidden)
			return
		}
		body = plain
	}

	var rec ScanRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		http.Error(w, "json parse: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !isSafeID(id) {
		http.Error(w, "invalid scan link", http.StatusBadRequest)
		return
	}
	link, err := loadLink(id)
	if err != nil {
		http.Error(w, "scan link not found", http.StatusNotFound)
		return
	}
	rec.LinkID = id
	rec.AdminUser = link.AdminUser

	if rec.ScanID == "" {
		rec.ScanID = genID()
	}
	if rec.Timestamp == "" {
		rec.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}

	storeMu.Lock()
	err = saveScan(&rec)
	storeMu.Unlock()
	if err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","scanId":"%s"}`, rec.ScanID)
}

func extractEncryptedEnvelope(body []byte) ([]byte, bool) {
	var env struct {
		Encrypted string `json:"encrypted"`
	}
	if err := json.Unmarshal(body, &env); err != nil || env.Encrypted == "" {
		return nil, false
	}
	return []byte(env.Encrypted), true
}

func handleViewScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/view/")
	rec, err := loadScan(id)
	if err != nil {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	renderScanDetail(w, rec)
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if len(q) > 256 {
		q = q[:256]
	}
	all := loadAllScans()
	var matched []ScanRecord
	qLower := strings.ToLower(q)
	for _, rec := range all {
		if rec.Steam != nil {
			for _, acct := range rec.Steam.Accounts {
				if strings.Contains(strings.ToLower(acct.SteamID), qLower) ||
					strings.Contains(strings.ToLower(acct.AccountName), qLower) {
					matched = append(matched, rec)
					break
				}
			}
		}
		if rec.Hardware != nil {
			if strings.Contains(strings.ToLower(rec.Hardware.HWID), qLower) ||
				strings.Contains(strings.ToLower(rec.Hardware.Hostname), qLower) ||
				strings.Contains(strings.ToLower(rec.Hardware.Username), qLower) {
				matched = append(matched, rec)
			}
		}
	}
	renderSearch(w, q, matched)
}

// handleDownload serves a customized scanner.exe with embedded config for the
// given link ID. The config is encrypted with the same build secret used by the
// scanner for uploads.
func handleDownload(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/dl/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	link, err := loadLink(id)
	if err != nil {
		http.Error(w, "link not found", http.StatusNotFound)
		return
	}

	scannerPath := scannerBinaryPath()
	baseData, err := os.ReadFile(scannerPath)
	if err != nil {
		logger.Error("scanner.exe not found", "path", scannerPath, "error", err)
		http.Error(w, "scanner.exe not found on server", http.StatusInternalServerError)
		return
	}

	origin := getOrigin(r)
	cfg := EmbeddedConfig{
		ScanID:         link.ID,
		UploadURL:      origin + "/api/scans/upload/" + link.ID,
		PlayerPassword: link.PlayerPassword,
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, "marshal config", http.StatusInternalServerError)
		return
	}

	enc, err := embedded.EncryptConfig(cfgJSON)
	if err != nil {
		logger.Error("encrypt embedded config failed", "error", err)
		http.Error(w, "encrypt config failed", http.StatusInternalServerError)
		return
	}

	// Append: marker + 4-byte length + encrypted blob
	out := make([]byte, 0, len(baseData)+len(configMarker)+4+len(enc))
	out = append(out, baseData...)
	out = append(out, []byte(configMarker)...)
	lenBytes := []byte{byte(len(enc)), byte(len(enc) >> 8), byte(len(enc) >> 16), byte(len(enc) >> 24)}
	out = append(out, lenBytes...)
	out = append(out, enc...)

	w.Header().Set("Content-Disposition", "attachment; filename=clover.exe")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
	w.Write(out)
}

func scannerBinaryPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "clover.exe"
	}
	return filepath.Join(filepath.Dir(exe), "clover.exe")
}

func getOrigin(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	host := r.Host
	// Check X-Forwarded-Proto for reverse proxy
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		proto = xfp
	}
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return proto + "://" + host
}

// ─── Escaping helper ───────────────────────────────────────────────────────

func esc(s string) string {
	return html.EscapeString(s)
}

// ─── Main ──────────────────────────────────────────────────────────────────

func main() {
	srvCfg = loadConfig()
	initStorage()

	if setupRequired() {
		logger.Warn("no admins configured; visit /setup to create the first admin account")
	}

	mux := http.NewServeMux()

	// Public routes (no auth)
	mux.HandleFunc("/setup", handleSetup)
	mux.HandleFunc("/login", withSetup(handleLogin))
	mux.HandleFunc("/logout", withSetup(handleLogout))
	mux.HandleFunc("/s/", withSetup(handleScanPage))       // player scan page
	mux.HandleFunc("/api/scans/upload/", withSetup(handleScanUpload)) // scanner upload
	mux.HandleFunc("/api/scan", withSetup(handleScanUpload)) // legacy scanner upload
	mux.HandleFunc("/api/scan/", withSetup(handleScanUpload))
	mux.HandleFunc("/dl/", withSetup(handleDownload)) // customized scanner download

	// Admin-only routes
	mux.HandleFunc("/", requireAuth(handleIndex))
	mux.HandleFunc("/api/links", requireAuth(handleCreateLink))
	mux.HandleFunc("/view/", requireAuth(handleViewScan))
	mux.HandleFunc("/search", requireAuth(handleSearch))

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	logger.Info("server listening", "addr", addr, "admins", len(srvCfg.Admins))
	server := &http.Server{Addr: addr, Handler: mux}
	go gracefulShutdown(server)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

func gracefulShutdown(srv *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	logger.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
