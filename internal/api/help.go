package api

import (
	"fmt"
	"net/http"
)

const helpText = `# certkit - X.509 Certificate Toolkit

A headless, agentic-first service for X.509 certificate operations.
No UI, no SDK. The API is the product.

## Endpoints

### GET /help
Returns this operating manual.

### GET /health
Returns service health status.

### POST /v1/inspect
Inspect a certificate and return all fields.
Body: PEM-encoded certificate (text/plain)
Response: key=value lines (one per field)

### POST /v1/generate
Generate a self-signed certificate and private key.
Query params:
  cn=<common name>          (required)
  org=<organization>
  ou=<organizational unit>
  country=<country code>
  province=<state/province>
  locality=<city>
  email=<email address>
  sans=<comma-separated DNS names or IPs>
  key_type=<rsa|ecdsa|ed25519>  (default: rsa)
  key_bits=<bits>               (rsa: 2048, ecdsa: 256/384/521)
  days=<validity days>          (default: 365)
  is_ca=<true|false>            (default: false)
Response: certificate PEM followed by private key PEM

### POST /v1/csr
Generate a Certificate Signing Request and private key.
Query params:
  cn=<common name>          (required)
  org=<organization>
  ou=<organizational unit>
  country=<country code>
  province=<state/province>
  locality=<city>
  sans=<comma-separated DNS names or IPs>
  key_type=<rsa|ecdsa|ed25519>  (default: rsa)
  key_bits=<bits>               (rsa: 2048, ecdsa: 256/384/521)
Response: CSR PEM followed by private key PEM

### POST /v1/csr/inspect
Inspect a CSR and return its fields.
Body: PEM-encoded CSR (text/plain)
Response: key=value lines (one per field)

### POST /v1/verify
Verify a certificate against a CA certificate.
Body: certificate PEM followed by "---CA---" separator and CA PEM(s)
Response: verification result

### POST /v1/expiry
Check certificate expiry.
Body: PEM-encoded certificate (text/plain)
Response: not_before, not_after, is_expired, days_until_expiry

### POST /v1/fingerprint
Get SHA-256 fingerprint of a certificate.
Body: PEM-encoded certificate (text/plain)
Response: fingerprint_sha256=<hex>

### POST /v1/convert
Convert between PEM and DER formats.
Query params:
  direction=<pem-to-der|der-to-pem>  (default: pem-to-der)
Body: certificate data (text/plain)
Response: converted format

## Response Formats
- Default: plain text (key=value lines, grepable, token-cheap)
- JSON: add Accept: application/json header or ?format=json

## Error Format
Errors include a hint telling you what to do next:
  error: <message>
  hint: <suggestion>
`

// handleHelp returns the operating manual.
func (s *Server) handleHelp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, helpText)
}

// handleHealth returns service health.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, fmt.Sprintf("status=ok\nservice=certkit\nversion=%s", s.cfg.Version))
}
