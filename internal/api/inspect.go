package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/relentlessworks/certkit/internal/model"
)

// handleInspect inspects a certificate.
func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
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

	cert, err := model.ParseCertificate(string(body))
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("failed to parse certificate: %v", err),
			"send a valid PEM-encoded X.509 certificate (starts with -----BEGIN CERTIFICATE-----)")
		return
	}

	info := model.ExtractCertInfo(cert)

	if wantsJSON(r) {
		jsonBytes, _ := json.MarshalIndent(info, "", "  ")
		writeJSON(w, http.StatusOK, string(jsonBytes))
		return
	}

	writeOK(w, r, model.FormatCertInfoPlain(info))
}

// handleCSRInspect inspects a CSR.
func (s *Server) handleCSRInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"send the CSR as the request body via POST")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			"failed to read request body",
			"ensure the CSR is sent as the request body")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"empty request body",
			"send a PEM-encoded CSR as the request body")
		return
	}

	csr, err := model.ParseCSR(string(body))
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("failed to parse CSR: %v", err),
			"send a valid PEM-encoded CSR (starts with -----BEGIN CERTIFICATE REQUEST-----)")
		return
	}

	info := model.ExtractCSRInfo(csr)

	if wantsJSON(r) {
		jsonBytes, _ := json.MarshalIndent(info, "", "  ")
		writeJSON(w, http.StatusOK, string(jsonBytes))
		return
	}

	writeOK(w, r, model.FormatCSRInfoPlain(info))
}
