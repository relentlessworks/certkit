package model

import (
	"strings"
	"testing"
)

func TestGenerateKeyRSA(t *testing.T) {
	key, pemStr, err := GenerateKey(KeyTypeRSA, 2048)
	if err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if !strings.Contains(pemStr, "BEGIN PRIVATE KEY") {
		t.Errorf("PEM output missing PRIVATE KEY header")
	}
}

func TestGenerateKeyECDSA(t *testing.T) {
	key, pemStr, err := GenerateKey(KeyTypeECDSA, 256)
	if err != nil {
		t.Fatalf("GenerateKey ECDSA failed: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if !strings.Contains(pemStr, "BEGIN PRIVATE KEY") {
		t.Errorf("PEM output missing PRIVATE KEY header")
	}
}

func TestGenerateKeyEd25519(t *testing.T) {
	key, pemStr, err := GenerateKey(KeyTypeEd25519, 0)
	if err != nil {
		t.Fatalf("GenerateKey Ed25519 failed: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if !strings.Contains(pemStr, "BEGIN PRIVATE KEY") {
		t.Errorf("PEM output missing PRIVATE KEY header")
	}
}

func TestGenerateKeyInvalidType(t *testing.T) {
	_, _, err := GenerateKey(KeyType("invalid"), 0)
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}
}

func TestGenerateSelfSigned(t *testing.T) {
	params := CertParams{
		CommonName: "test.example.com",
		DNSNames:   []string{"test.example.com"},
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, keyPEM, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") {
		t.Errorf("cert PEM missing CERTIFICATE header")
	}
	if !strings.Contains(keyPEM, "BEGIN PRIVATE KEY") {
		t.Errorf("key PEM missing PRIVATE KEY header")
	}

	// Verify the certificate can be parsed back
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", cert.Subject.CommonName)
	}
}

func TestGenerateSelfSignedCA(t *testing.T) {
	params := CertParams{
		CommonName: "Test CA",
		KeyType:    KeyTypeECDSA,
		KeyBits:    256,
		Days:       3650,
		IsCA:       true,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned CA failed: %v", err)
	}

	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("failed to parse generated CA certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
}

func TestGenerateCSR(t *testing.T) {
	params := CSRParams{
		CommonName: "test.example.com",
		DNSNames:   []string{"test.example.com"},
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
	}

	csrPEM, keyPEM, err := GenerateCSR(params)
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}

	if !strings.Contains(csrPEM, "BEGIN CERTIFICATE REQUEST") {
		t.Errorf("CSR PEM missing CERTIFICATE REQUEST header")
	}
	if !strings.Contains(keyPEM, "BEGIN PRIVATE KEY") {
		t.Errorf("key PEM missing PRIVATE KEY header")
	}

	// Verify the CSR can be parsed back
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("failed to parse generated CSR: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got '%s'", csr.Subject.CommonName)
	}
}

func TestParseCertificateInvalid(t *testing.T) {
	_, err := ParseCertificate("not a certificate")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestParsePrivateKey(t *testing.T) {
	_, keyPEM, err := GenerateKey(KeyTypeRSA, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	key, err := ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
}

func TestExtractCertInfo(t *testing.T) {
	params := CertParams{
		CommonName: "info.test.com",
		DNSNames:   []string{"info.test.com", "alt.test.com"},
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	info := ExtractCertInfo(cert)

	if info.Subject == "" {
		t.Error("expected non-empty subject")
	}
	if info.FingerprintSHA256 == "" {
		t.Error("expected non-empty SHA256 fingerprint")
	}
	if info.PublicKeyBits != 2048 {
		t.Errorf("expected 2048 bits, got %d", info.PublicKeyBits)
	}
	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}
}

func TestFormatCertInfoPlain(t *testing.T) {
	params := CertParams{
		CommonName: "format.test.com",
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	info := ExtractCertInfo(cert)
	output := FormatCertInfoPlain(info)

	if !strings.Contains(output, "subject=") {
		t.Error("expected 'subject=' in output")
	}
	if !strings.Contains(output, "issuer=") {
		t.Error("expected 'issuer=' in output")
	}
	if !strings.Contains(output, "fingerprint_sha256=") {
		t.Error("expected 'fingerprint_sha256=' in output")
	}
}

func TestCheckExpiry(t *testing.T) {
	params := CertParams{
		CommonName: "expiry.test.com",
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	notBefore, notAfter, isExpired, daysUntil, err := CheckExpiry(certPEM)
	if err != nil {
		t.Fatalf("CheckExpiry failed: %v", err)
	}

	if isExpired {
		t.Error("expected certificate not to be expired")
	}
	if daysUntil < 364 {
		t.Errorf("expected ~365 days until expiry, got %d", daysUntil)
	}
	if notBefore.IsZero() {
		t.Error("expected non-zero NotBefore")
	}
	if notAfter.IsZero() {
		t.Error("expected non-zero NotAfter")
	}
}

func TestGetFingerprint(t *testing.T) {
	params := CertParams{
		CommonName: "fp.test.com",
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	fp, err := GetFingerprint(certPEM)
	if err != nil {
		t.Fatalf("GetFingerprint failed: %v", err)
	}

	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestParseSANs(t *testing.T) {
	dns, ips := ParseSANs("example.com,10.0.0.1,foo.bar.com,192.168.1.1")
	if len(dns) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(dns))
	}
	if len(ips) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(ips))
	}
}

func TestConvertPEMToDER(t *testing.T) {
	params := CertParams{
		CommonName: "convert.test.com",
		KeyType:    KeyTypeRSA,
		KeyBits:    2048,
		Days:       365,
	}

	certPEM, _, err := GenerateSelfSigned(params)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	hex, err := ConvertPEMToDER(certPEM)
	if err != nil {
		t.Fatalf("ConvertPEMToDER failed: %v", err)
	}

	if hex == "" {
		t.Error("expected non-empty hex output")
	}

	// Convert back
	pem2, err := ConvertDERToPEM(hex)
	if err != nil {
		t.Fatalf("ConvertDERToPEM failed: %v", err)
	}

	if !strings.Contains(pem2, "BEGIN CERTIFICATE") {
		t.Error("expected CERTIFICATE header in round-trip")
	}
}

func TestVerifyChain(t *testing.T) {
	// Generate a CA
	caParams := CertParams{
		CommonName: "Test Root CA",
		KeyType:    KeyTypeECDSA,
		KeyBits:    256,
		Days:       3650,
		IsCA:       true,
	}
	caCertPEM, _, err := GenerateSelfSigned(caParams)
	if err != nil {
		t.Fatalf("GenerateSelfSigned CA failed: %v", err)
	}

	// Verify the CA against itself
	err = VerifyChain(caCertPEM, []string{caCertPEM})
	if err != nil {
		t.Errorf("VerifyChain failed for self-signed CA: %v", err)
	}
}
