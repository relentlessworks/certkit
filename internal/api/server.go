package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/relentlessworks/certkit/internal/config"
)

// Server holds the HTTP server and configuration.
type Server struct {
	cfg    config.Config
	mux    *http.ServeMux
}

// New creates a new API server.
func New(cfg config.Config) *Server {
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

// routes registers all HTTP routes.
func (s *Server) routes() {
	s.mux.HandleFunc("/help", s.handleHelp)
	s.mux.HandleFunc("/.well-known/agent.md", s.handleHelp)
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/v1/inspect", s.handleInspect)
	s.mux.HandleFunc("/v1/generate", s.handleGenerate)
	s.mux.HandleFunc("/v1/csr", s.handleCSR)
	s.mux.HandleFunc("/v1/csr/inspect", s.handleCSRInspect)
	s.mux.HandleFunc("/v1/verify", s.handleVerify)
	s.mux.HandleFunc("/v1/expiry", s.handleExpiry)
	s.mux.HandleFunc("/v1/fingerprint", s.handleFingerprint)
	s.mux.HandleFunc("/v1/convert", s.handleConvert)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	addr := s.cfg.Addr()
	log.Printf("certkit v%s starting on http://%s", s.cfg.Version, addr)
	return http.ListenAndServe(addr, s.loggingMiddleware(s.mux))
}

// loggingMiddleware logs each request.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// wantsJSON returns true if the client requested JSON response.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	return false
}

// writePlain writes a plain text response.
func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}

// writeError writes an error response with a hint.
func writeError(w http.ResponseWriter, r *http.Request, status int, msg string, hint string) {
	if wantsJSON(r) {
		body := fmt.Sprintf(`{"error":"%s","hint":"%s"}`, escapeJSON(msg), escapeJSON(hint))
		writeJSON(w, status, body)
	} else {
		writePlain(w, status, fmt.Sprintf("error: %s\nhint: %s", msg, hint))
	}
}

// writeOK writes a success response.
func writeOK(w http.ResponseWriter, r *http.Request, body string) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, body)
	} else {
		writePlain(w, http.StatusOK, body)
	}
}

// escapeJSON escapes a string for JSON output.
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
