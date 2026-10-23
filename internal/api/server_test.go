package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/relentlessworks/certkit/internal/config"
)

func newTestServer() *httptest.Server {
	cfg := config.Default()
	s := New(cfg)
	return httptest.NewServer(s.mux)
}

func TestHealth(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "status=ok") {
		t.Errorf("expected 'status=ok' in response, got: %s", string(body))
	}
}

func TestHelp(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/help")
	if err != nil {
		t.Fatalf("GET /help failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "certkit") {
		t.Errorf("expected 'certkit' in help text")
	}
}

func TestGenerateCert(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/generate?cn=test.example.com&key_type=rsa&key_bits=2048&days=365",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "BEGIN CERTIFICATE") {
		t.Error("expected CERTIFICATE in response")
	}
	if !strings.Contains(bodyStr, "BEGIN PRIVATE KEY") {
		t.Error("expected PRIVATE KEY in response")
	}
}

func TestGenerateCertMissingCN(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/generate", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hint:") {
		t.Error("expected hint in error response")
	}
}

func TestGenerateECDSA(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/generate?cn=ecdsa.test.com&key_type=ecdsa&key_bits=256",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Error("expected CERTIFICATE in response")
	}
}

func TestGenerateEd25519(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/generate?cn=ed.test.com&key_type=ed25519",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Error("expected CERTIFICATE in response")
	}
}

func TestGenerateCA(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/generate?cn=Test%20CA&key_type=ecdsa&key_bits=256&is_ca=true",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Error("expected CERTIFICATE in response")
	}
}

func TestGenerateCSR(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/csr?cn=csr.test.com&key_type=rsa&key_bits=2048",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/csr failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if !strings.Contains(bodyStr, "BEGIN CERTIFICATE REQUEST") {
		t.Error("expected CERTIFICATE REQUEST in response")
	}
	if !strings.Contains(bodyStr, "BEGIN PRIVATE KEY") {
		t.Error("expected PRIVATE KEY in response")
	}
}

func TestInspectCert(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// First generate a cert
	resp, err := http.Post(srv.URL+"/v1/generate?cn=inspect.test.com&key_type=rsa&key_bits=2048",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Extract just the certificate PEM
	certPEM := strings.SplitN(string(body), "BEGIN PRIVATE KEY", 2)[0]
	certPEM = strings.TrimSpace(certPEM)

	// Now inspect it
	resp2, err := http.Post(srv.URL+"/v1/inspect", "text/plain", strings.NewReader(certPEM))
	if err != nil {
		t.Fatalf("POST /v1/inspect failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr := string(body2)

	if !strings.Contains(bodyStr, "subject=") {
		t.Error("expected 'subject=' in inspect response")
	}
	if !strings.Contains(bodyStr, "fingerprint_sha256=") {
		t.Error("expected 'fingerprint_sha256=' in inspect response")
	}
}

func TestInspectCertJSON(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// First generate a cert
	resp, err := http.Post(srv.URL+"/v1/generate?cn=json.test.com&key_type=rsa&key_bits=2048",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	certPEM := strings.SplitN(string(body), "BEGIN PRIVATE KEY", 2)[0]
	certPEM = strings.TrimSpace(certPEM)

	// Inspect with JSON
	req, _ := http.NewRequest("POST", srv.URL+"/v1/inspect", strings.NewReader(certPEM))
	req.Header.Set("Accept", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/inspect failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), "{") {
		t.Error("expected JSON response")
	}
}

func TestExpiry(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// Generate a cert
	resp, err := http.Post(srv.URL+"/v1/generate?cn=expiry.test.com&key_type=rsa&key_bits=2048&days=365",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	certPEM := strings.SplitN(string(body), "BEGIN PRIVATE KEY", 2)[0]
	certPEM = strings.TrimSpace(certPEM)

	// Check expiry
	resp2, err := http.Post(srv.URL+"/v1/expiry", "text/plain", strings.NewReader(certPEM))
	if err != nil {
		t.Fatalf("POST /v1/expiry failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	bodyStr := string(body2)

	if !strings.Contains(bodyStr, "not_before=") {
		t.Error("expected 'not_before=' in response")
	}
	if !strings.Contains(bodyStr, "not_after=") {
		t.Error("expected 'not_after=' in response")
	}
	if !strings.Contains(bodyStr, "is_expired=") {
		t.Error("expected 'is_expired=' in response")
	}
}

func TestFingerprint(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// Generate a cert
	resp, err := http.Post(srv.URL+"/v1/generate?cn=fp.test.com&key_type=rsa&key_bits=2048",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	certPEM := strings.SplitN(string(body), "BEGIN PRIVATE KEY", 2)[0]
	certPEM = strings.TrimSpace(certPEM)

	// Get fingerprint
	resp2, err := http.Post(srv.URL+"/v1/fingerprint", "text/plain", strings.NewReader(certPEM))
	if err != nil {
		t.Fatalf("POST /v1/fingerprint failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), "fingerprint_sha256=") {
		t.Error("expected 'fingerprint_sha256=' in response")
	}
}

func TestInspectInvalidCert(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/inspect", "text/plain", strings.NewReader("not a certificate"))
	if err != nil {
		t.Fatalf("POST /v1/inspect failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hint:") {
		t.Error("expected hint in error response")
	}
}

func TestVerifySelfSigned(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	// Generate a CA
	resp, err := http.Post(srv.URL+"/v1/generate?cn=Test%20CA&key_type=ecdsa&key_bits=256&is_ca=true",
		"text/plain", nil)
	if err != nil {
		t.Fatalf("POST /v1/generate failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	certPEM := strings.SplitN(string(body), "BEGIN PRIVATE KEY", 2)[0]
	certPEM = strings.TrimSpace(certPEM)

	// Verify against itself
	verifyBody := certPEM + "\n---CA---\n" + certPEM
	resp2, err := http.Post(srv.URL+"/v1/verify", "text/plain", strings.NewReader(verifyBody))
	if err != nil {
		t.Fatalf("POST /v1/verify failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}

	body2, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body2), "valid=true") {
		t.Errorf("expected valid=true, got: %s", string(body2))
	}
}
