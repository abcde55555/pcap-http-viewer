// Package web serves the embedded SPA and the JSON/SSE API.
package web

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"pcap-http-viewer/internal/app"
	"pcap-http-viewer/internal/plugins"
	"pcap-http-viewer/internal/repeater"
)

// Server holds HTTP handlers and shared state.
type Server struct {
	app    *app.App
	assets fs.FS
}

// NewServer creates a server. If assets is nil the current working web dir is
// used (dev mode).
func NewServer(a *app.App, assets embed.FS) *Server {
	sub, err := fs.Sub(assets, "web")
	if err != nil {
		panic(err)
	}
	return &Server{app: a, assets: sub}
}

// Routes returns the configured mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/open", s.handleOpen)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/progress", s.handleProgress)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/session/", s.handleSession)
	mux.HandleFunc("/api/streams", s.handleStreams)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/repeater/send", s.handleRepeaterSend)
	mux.HandleFunc("/api/repeater/seed", s.handleRepeaterSeed)
	mux.HandleFunc("/api/repeater/ws/connect", s.handleWSConnect)
	mux.HandleFunc("/api/repeater/ws/events", s.handleWSEvents)
	mux.HandleFunc("/api/repeater/ws/send", s.handleWSSend)
	mux.HandleFunc("/api/repeater/ws/close", s.handleWSClose)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/import", s.handleRulesImport)
	mux.HandleFunc("/api/rules/export", s.handleRulesExport)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.Handle("/", http.FileServer(http.FS(s.assets)))

	return logging(mux)
}

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			start := time.Now()
			h.ServeHTTP(w, r)
			_ = start
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

// handleOpen: POST /api/open?path=<file>
func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		// Also accept JSON body {"path":"..."}.
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			path = body.Path
		}
	}
	if path == "" {
		http.Error(w, "missing path", http.StatusBadRequest)
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.app.Open(abs); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "path": abs})
}

// handleRepeaterSend: POST /api/repeater/send — sends an edited request.
func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req repeater.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := repeater.Send(&req)
	writeJSON(w, http.StatusOK, resp)
}

// handleRepeaterSeed: GET /api/repeater/seed?id=N — returns editable raw request
// text for a captured transaction (gzip already decoded by the parser).
func (s *Server) handleRepeaterSeed(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	det, err := s.app.Store().Detail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Fetch the (already-decoded) request body.
	var body []byte
	if det.RequestBody.Length > 0 {
		body, _ = s.app.Store().ReadBody(id, "req", 0, det.RequestBody.Length)
	}
	// Bodies in storage are already content-decoded, so pass encoding empty.
	// net/http stores Host separately (not in Header); ensure it's present.
	if det.Host != "" {
		if det.RequestHeader == nil {
			det.RequestHeader = map[string]string{}
		}
		if _, ok := det.RequestHeader["Host"]; !ok {
			det.RequestHeader["Host"] = det.Host
		}
	}
	scheme, host, raw := repeater.Seed(det.Method, det.URL, det.HTTPVersion, det.RequestHeader, body, "")
	writeJSON(w, http.StatusOK, map[string]any{
		"scheme": scheme, "host": host,
		"rawBase64": base64.StdEncoding.EncodeToString(raw),
		"method":    det.Method, "url": det.URL,
	})
}

// handleWSConnect: POST /api/repeater/ws/connect — opens a WebSocket to the
// target described by the raw upgrade request and returns a connection id.
func (s *Server) handleWSConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req repeater.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.RawB64)
	if err != nil {
		http.Error(w, "bad base64", http.StatusBadRequest)
		return
	}
	if !repeater.IsWSUpgrade(raw) {
		http.Error(w, "not a websocket upgrade request", http.StatusBadRequest)
		return
	}
	c, err := repeater.WSConnect(req.Scheme, req.Host, raw, req.Options)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": c.ID, "target": c.Target})
}

// handleWSEvents: GET /api/repeater/ws/events?id=... — SSE stream of frames.
func (s *Server) handleWSEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	c := repeater.WSGet(r.URL.Query().Get("id"))
	if c == nil {
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	repeater.WSServeEvents(r.Context(), c, func(b []byte) error {
		_, err := fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
		return err
	})
}

// handleWSSend: POST /api/repeater/ws/send {id, data, binary}
func (s *Server) handleWSSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID     string `json:"id"`
		Data   string `json:"data"`
		Binary bool   `json:"binary"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := repeater.WSGet(body.ID)
	if c == nil {
		http.Error(w, "no such connection", http.StatusNotFound)
		return
	}
	if err := c.Send(body.Data, body.Binary); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleWSClose: POST /api/repeater/ws/close {id}
func (s *Server) handleWSClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct{ ID string `json:"id"` }
	_ = json.NewDecoder(r.Body).Decode(&body)
	repeater.WSClose(body.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleScan: POST /api/scan — manually run the sensitive-info scanner over
// the currently loaded capture. Scanning is opt-in, not run on parse.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.app.ScanNow(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

// handleUpload: POST multipart/form-data with field "file" — writes the capture
// to a temp file and starts parsing it. Useful when the browser cannot provide a
// real filesystem path.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(1 << 30); err != nil { // 1 GiB
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	dst, err := os.CreateTemp("", "upload-*"+filepath.Ext(header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(dst, file); err != nil {
		dst.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dst.Close()
	if err := s.app.Open(dst.Name()); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "path": dst.Name()})
}

// handleProgress: GET /api/progress (SSE)
func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsub := s.app.Subscribe()
	defer unsub()

	// Heartbeat to keep proxies happy.
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(p)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

// handleSessions: GET /api/sessions -> NDJSON metadata
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	store := s.app.Store()
	enc := json.NewEncoder(w)
	for _, m := range store.Metadata() {
		if err := enc.Encode(m); err != nil {
			return
		}
	}
}

// handleSession: /api/session/{id}  (detail)
//                /api/session/{id}/body?side=req|resp&offset=&limit=
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/session/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if len(parts) == 2 && parts[1] == "body" {
		s.handleBody(w, r, id)
		return
	}
	detail, err := s.app.Store().Detail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleBody(w http.ResponseWriter, r *http.Request, id int64) {
	side := r.URL.Query().Get("side")
	if side == "" {
		side = "resp"
	}
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	if limit <= 0 {
		limit = 256 * 1024 // default 256 KiB
	}
	data, err := s.app.Store().ReadBody(id, side, offset, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	det, _ := s.app.Store().Detail(id)
	ct := "application/octet-stream"
	if det != nil {
		if side == "req" {
			ct = det.RequestHeader["Content-Type"]
		} else {
			ct = det.ResponseHeader["Content-Type"]
		}
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleStreams: GET /api/streams -> stream summaries
func (s *Server) handleStreams(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Store().StreamSummaries())
}

// handleFindings: GET /api/findings?rule=id -> findings grouped by rule
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	rule := r.URL.Query().Get("rule")
	writeJSON(w, http.StatusOK, s.app.Store().AllFindings(rule))
}

// handleStatus: GET /api/status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"file":      s.app.CurrentFile(),
		"count":     s.app.Store().Count(),
		"parsing":   s.app.IsParsing(),
		"rules":     len(s.app.Sensitive().Rules()),
	})
}

// handleRules: GET (list) / PUT (replace)
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rules := s.app.Sensitive().Rules()
		out := make([]map[string]any, 0, len(rules))
		for _, rule := range rules {
			out = append(out, plugins.RuleToMap(rule))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPut, http.MethodPost:
		var raw []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rules := make([]*plugins.Rule, 0, len(raw))
		for _, m := range raw {
			rules = append(rules, plugins.MapToRule(m))
		}
		if errs := s.app.UpdateRules(rules); len(errs) > 0 {
			msgs := make([]string, len(errs))
			for i, e := range errs {
				msgs[i] = e.Error()
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": msgs})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(rules)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()
	buf := make([]byte, 1<<20)
	n, _ := file.Read(buf)
	rules, err := plugins.LoadRules(buf[:n])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errs := s.app.UpdateRules(rules); len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": msgs})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(rules)})
}

func (s *Server) handleRulesExport(w http.ResponseWriter, r *http.Request) {
	rules := s.app.Sensitive().Rules()
	data, err := plugins.MarshalRulesYAML(rules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="sensitive-rules.yaml"`)
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Listen starts the HTTP server on a random local port and returns the URL.
func (s *Server) Listen() (string, *http.Server, error) {
	return s.ListenAddr("127.0.0.1:0")
}

// ListenAddr starts the HTTP server on the given address and returns the URL.
func (s *Server) ListenAddr(addr string) (string, *http.Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: s.Routes()}
	go func() { _ = srv.Serve(ln) }()
	url := "http://" + ln.Addr().String() + "/"
	return url, srv, nil
}

// OpenBrowser opens url in the system default browser.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
