package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/relentlessworks/certkit/internal/model"
)

// handleVerify verifies a certificate against a CA.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"send the certificate and CA via POST body")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			"failed to read request body",
			"ensure the request body contains the certificate and CA")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"empty request body",
			"send the certificate PEM, then ---CA--- separator, then CA PEM(s)")
		return
	}

	// Split on ---CA--- separator
	parts := strings.Split(string(body), "---CA---")
	if len(parts) < 2 {
		writeError(w, r, http.StatusBadRequest,
			"missing CA certificate",
			"include the CA certificate after a ---CA--- separator line")
		return
	}

	certPEM := strings.TrimSpace(parts[0])
	if certPEM == "" {
		writeError(w, r, http.StatusBadRequest,
			"missing certificate to verify",
			"send the certificate PEM before the ---CA--- separator")
		return
	}

	var caPEMs []string
	for i := 1; i < len(parts); i++ {
		ca := strings.TrimSpace(parts[i])
		if ca != "" {
			caPEMs = append(caPEMs, ca)
		}
	}

	if len(caPEMs) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"missing CA certificate",
			"include at least one CA certificate after the ---CA--- separator")
		return
	}

	err = model.VerifyChain(certPEM, caPEMs)
	if err != nil {
		writeOK(w, r, fmt.Sprintf("valid=false\nerror=%v", err))
		return
	}

	writeOK(w, r, "valid=true\nmessage=certificate verified successfully")
}
