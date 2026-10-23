package api

import (
	"fmt"
	"io"
	"net/http"

	"github.com/relentlessworks/certkit/internal/model"
)

// handleConvert converts between PEM and DER formats.
func (s *Server) handleConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"send the certificate data as the request body via POST")
		return
	}

	q := r.URL.Query()
	direction := q.Get("direction")
	if direction == "" {
		direction = "pem-to-der"
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest,
			"failed to read request body",
			"ensure the certificate data is sent as the request body")
		return
	}
	defer r.Body.Close()

	if len(body) == 0 {
		writeError(w, r, http.StatusBadRequest,
			"empty request body",
			"send certificate data as the request body")
		return
	}

	switch direction {
	case "pem-to-der":
		result, err := model.ConvertPEMToDER(string(body))
		if err != nil {
			writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("failed to convert PEM to DER: %v", err),
				"send a valid PEM-encoded certificate")
			return
		}
		writeOK(w, r, fmt.Sprintf("format=der\nhex=%s", result))

	case "der-to-pem":
		result, err := model.ConvertDERToPEM(string(body))
		if err != nil {
			writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("failed to convert DER to PEM: %v", err),
				"send a valid hex-encoded DER certificate")
			return
		}
		writeOK(w, r, result)

	default:
		writeError(w, r, http.StatusBadRequest,
			fmt.Sprintf("unknown direction: %s", direction),
			"direction must be 'pem-to-der' or 'der-to-pem'")
	}
}
