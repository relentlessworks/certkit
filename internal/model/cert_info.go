package model

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// CertInfo holds the extracted information from a certificate.
type CertInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	NotBefore          time.Time
	NotAfter           time.Time
	IsCA               bool
	KeyUsage           []string
	ExtKeyUsage        []string
	SANs               []string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	FingerprintSHA256  string
	FingerprintSHA1    string
	Version            int
	IsExpired          bool
	DaysUntilExpiry    int
	SubjectKeyID       string
	AuthorityKeyID     string
}

// ExtractCertInfo extracts all relevant information from a certificate.
func ExtractCertInfo(cert *x509.Certificate) CertInfo {
	now := time.Now()
	daysUntil := int(cert.NotAfter.Sub(now).Hours() / 24)

	info := CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		Version:            cert.Version,
		IsExpired:          now.After(cert.NotAfter),
		DaysUntilExpiry:    daysUntil,
	}

	// Key usage
	info.KeyUsage = formatKeyUsage(cert.KeyUsage)

	// Extended key usage
	for _, eku := range cert.ExtKeyUsage {
		info.ExtKeyUsage = append(info.ExtKeyUsage, formatExtKeyUsage(eku))
	}

	// SANs
	info.SANs = cert.DNSNames
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		info.SANs = append(info.SANs, email)
	}
	for _, uri := range cert.URIs {
		info.SANs = append(info.SANs, uri.String())
	}

	// Public key bits
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Params().BitSize
	case ed25519.PublicKey:
		info.PublicKeyBits = 256
	}

	// Fingerprints
	fp256 := sha256.Sum256(cert.Raw)
	info.FingerprintSHA256 = fmt.Sprintf("%x", fp256[:])

	fp1 := sha1.Sum(cert.Raw)
	info.FingerprintSHA1 = fmt.Sprintf("%x", fp1[:])

	// Key IDs
	if len(cert.SubjectKeyId) > 0 {
		info.SubjectKeyID = fmt.Sprintf("%x", cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = fmt.Sprintf("%x", cert.AuthorityKeyId)
	}

	return info
}

// FormatCertInfoPlain formats certificate info as plain text (one key=value per line).
func FormatCertInfoPlain(info CertInfo) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("subject=%s", info.Subject))
	lines = append(lines, fmt.Sprintf("issuer=%s", info.Issuer))
	lines = append(lines, fmt.Sprintf("serial=%s", info.SerialNumber))
	lines = append(lines, fmt.Sprintf("not_before=%s", info.NotBefore.Format(time.RFC3339)))
	lines = append(lines, fmt.Sprintf("not_after=%s", info.NotAfter.Format(time.RFC3339)))
	lines = append(lines, fmt.Sprintf("is_ca=%v", info.IsCA))
	lines = append(lines, fmt.Sprintf("version=%d", info.Version))
	lines = append(lines, fmt.Sprintf("sig_algo=%s", info.SignatureAlgorithm))
	lines = append(lines, fmt.Sprintf("pubkey_algo=%s", info.PublicKeyAlgorithm))
	lines = append(lines, fmt.Sprintf("pubkey_bits=%d", info.PublicKeyBits))
	if len(info.KeyUsage) > 0 {
		lines = append(lines, fmt.Sprintf("key_usage=%s", strings.Join(info.KeyUsage, ",")))
	}
	if len(info.ExtKeyUsage) > 0 {
		lines = append(lines, fmt.Sprintf("ext_key_usage=%s", strings.Join(info.ExtKeyUsage, ",")))
	}
	if len(info.SANs) > 0 {
		lines = append(lines, fmt.Sprintf("sans=%s", strings.Join(info.SANs, ",")))
	}
	lines = append(lines, fmt.Sprintf("fingerprint_sha256=%s", info.FingerprintSHA256))
	lines = append(lines, fmt.Sprintf("fingerprint_sha1=%s", info.FingerprintSHA1))
	if info.SubjectKeyID != "" {
		lines = append(lines, fmt.Sprintf("subject_key_id=%s", info.SubjectKeyID))
	}
	if info.AuthorityKeyID != "" {
		lines = append(lines, fmt.Sprintf("authority_key_id=%s", info.AuthorityKeyID))
	}
	lines = append(lines, fmt.Sprintf("is_expired=%v", info.IsExpired))
	lines = append(lines, fmt.Sprintf("days_until_expiry=%d", info.DaysUntilExpiry))
	return strings.Join(lines, "\n")
}

// ParseCSR parses a PEM encoded Certificate Signing Request.
func ParseCSR(input string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(input))
	if block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("expected CERTIFICATE REQUEST PEM block, got %s", block.Type)
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSR: %w", err)
		}
		return csr, nil
	}

	csr, err := x509.ParseCertificateRequest([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("input is not valid PEM or DER CSR: %w", err)
	}
	return csr, nil
}

// CSRInfo holds extracted CSR information.
type CSRInfo struct {
	Subject            string
	SignatureAlgorithm string
	PublicKeyAlgorithm string
	PublicKeyBits       int
	SANs               []string
}

// ExtractCSRInfo extracts information from a CSR.
func ExtractCSRInfo(csr *x509.CertificateRequest) CSRInfo {
	info := CSRInfo{
		Subject:            csr.Subject.String(),
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm.String(),
	}

	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		info.PublicKeyBits = key.N.BitLen()
	case *ecdsa.PublicKey:
		info.PublicKeyBits = key.Params().BitSize
	case ed25519.PublicKey:
		info.PublicKeyBits = 256
	}

	info.SANs = csr.DNSNames
	for _, ip := range csr.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}
	for _, email := range csr.EmailAddresses {
		info.SANs = append(info.SANs, email)
	}
	for _, uri := range csr.URIs {
		info.SANs = append(info.SANs, uri.String())
	}

	return info
}

// FormatCSRInfoPlain formats CSR info as plain text.
func FormatCSRInfoPlain(info CSRInfo) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("subject=%s", info.Subject))
	lines = append(lines, fmt.Sprintf("sig_algo=%s", info.SignatureAlgorithm))
	lines = append(lines, fmt.Sprintf("pubkey_algo=%s", info.PublicKeyAlgorithm))
	lines = append(lines, fmt.Sprintf("pubkey_bits=%d", info.PublicKeyBits))
	if len(info.SANs) > 0 {
		lines = append(lines, fmt.Sprintf("sans=%s", strings.Join(info.SANs, ",")))
	}
	return strings.Join(lines, "\n")
}

func formatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

func formatExtKeyUsage(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	default:
		return fmt.Sprintf("Unknown(%d)", eku)
	}
}
