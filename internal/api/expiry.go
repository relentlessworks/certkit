package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/relentlessworks/certkit/internal/model"
)

// handleExpiry checks certificate expiry.
func (s *Server) handleExpiry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"send the certificate as the request body via POST")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			"failed to read request body",
			"ensure the certificate is sent as the request body")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"empty request body",
			"send a PEM-encoded certificate as the request body")
		return
	}

	notBefore, notAfter, isExpired, daysUntil, err := model.CheckExpiry(string(body))
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("failed to parse certificate: %v", err),
			"send a valid PEM-encoded X.509 certificate")
		return
	}

	result := map[string]interface{}{
		"not_before":       notBefore.Format(time.RFC3339),
		"not_after":        notAfter.Format(time.RFC3339),
		"is_expired":       isExpired,
		"days_until_expiry": daysUntil,
	}

	if wantsJSON(r) {
		jsonBytes, _ := json.MarshalIndent(result, "", "  ")
		writeJSON(w, http.StatusOK, string(jsonBytes))
		return
	}

	output := fmt.Sprintf("not_before=%s\nnot_after=%s\nis_expired=%v\ndays_until_expiry=%d",
		notBefore.Format(time.RFC3339),
		notAfter.Format(time.RFC3339),
		isExpired,
		daysUntil)
	writeOK(w, r, output)
}

// handleFingerprint returns the SHA-256 fingerprint of a certificate.
func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"send the certificate as the request body via POST")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			"failed to read request body",
			"ensure the certificate is sent as the request body")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"empty request body",
			"send a PEM-encoded certificate as the request body")
		return
	}

	fp, err := model.GetFingerprint(string(body))
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("failed to parse certificate: %v", err),
			"send a valid PEM-encoded X.509 certificate")
		return
	}

	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, fmt.Sprintf(`{"fingerprint_sha256":"%s"}`, fp))
		return
	}

	writeOK(w, r, fmt.Sprintf("fingerprint_sha256=%s", fp))
}
