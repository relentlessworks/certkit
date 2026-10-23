package model

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// KeyType represents the type of key to generate.
type KeyType string

const (
	KeyTypeRSA     KeyType = "rsa"
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeEd25519 KeyType = "ed25519"
)

// GenerateKey generates a private key of the specified type and returns PEM-encoded key.
func GenerateKey(keyType KeyType, bits int) (interface{}, string, error) {
	switch keyType {
	case KeyTypeRSA:
		if bits == 0 {
			bits = 2048
		}
		if bits < 512 {
			return nil, "", fmt.Errorf("RSA key size must be at least 512 bits")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate RSA key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal RSA key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return key, string(pemBytes), nil

	case KeyTypeECDSA:
		var curve elliptic.Curve
		if bits == 0 || bits == 256 {
			curve = elliptic.P256()
		} else if bits == 384 {
			curve = elliptic.P384()
		} else if bits == 521 {
			curve = elliptic.P521()
		} else {
			return nil, "", fmt.Errorf("ECDSA key size must be 256, 384, or 521 bits")
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal ECDSA key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return key, string(pemBytes), nil

	case KeyTypeEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		_ = pub
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, "", fmt.Errorf("failed to marshal Ed25519 key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		return priv, string(pemBytes), nil

	default:
		return nil, "", fmt.Errorf("unknown key type: %s (valid: rsa, ecdsa, ed25519)", keyType)
	}
}

// ParsePrivateKey parses a PEM-encoded private key.
func ParsePrivateKey(input string) (interface{}, error) {
	block, _ := pem.Decode([]byte(input))
	if block == nil {
		return nil, fmt.Errorf("input is not valid PEM")
	}

	var key interface{}
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return key, nil
}

// CertParams holds parameters for generating a self-signed certificate.
type CertParams struct {
	CommonName      string
	Organization    string
	OrganizationalUnit string
	Country         string
	Province        string
	Locality        string
	EmailAddress    string
	DNSNames        []string
	IPAddresses     []string
	EmailAddresses  []string
	URIs            []string
	KeyType         KeyType
	KeyBits         int
	Days            int
	IsCA            bool
}

// GenerateSelfSigned generates a self-signed certificate and private key.
func GenerateSelfSigned(params CertParams) (certPEM string, keyPEM string, err error) {
	if params.Days == 0 {
		params.Days = 365
	}
	if params.KeyType == "" {
		params.KeyType = KeyTypeRSA
	}

	// Generate key
	key, keyStr, err := GenerateKey(params.KeyType, params.KeyBits)
	if err != nil {
		return "", "", err
	}
	keyPEM = keyStr

	// Build subject
	subject := pkix.Name{
		CommonName: params.CommonName,
	}
	if params.Organization != "" {
		subject.Organization = []string{params.Organization}
	}
	if params.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{params.OrganizationalUnit}
	}
	if params.Country != "" {
		subject.Country = []string{params.Country}
	}
	if params.Province != "" {
		subject.Province = []string{params.Province}
	}
	if params.Locality != "" {
		subject.Locality = []string{params.Locality}
	}
	// EmailAddress is handled separately via the certificate template

	// Parse IPs
	var ips []net.IP
	for _, ipStr := range params.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "", "", fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ips = append(ips, ip)
	}

	// Parse email addresses
	var emails []string
	for _, e := range params.EmailAddresses {
		if params.EmailAddress != "" && e == params.EmailAddress {
			emails = append(emails, e)
			continue
		}
		if _, err := mail.ParseAddress(e); err != nil {
			return "", "", fmt.Errorf("invalid email address: %s", e)
		}
		emails = append(emails, e)
	}
	if params.EmailAddress != "" && len(emails) == 0 {
		emails = []string{params.EmailAddress}
	}

	// Parse URIs
	var uris []*url.URL
	for _, uriStr := range params.URIs {
		u, err := url.Parse(uriStr)
		if err != nil {
			return "", "", fmt.Errorf("invalid URI: %s", uriStr)
		}
		uris = append(uris, u)
	}

	// Serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(params.Days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     params.DNSNames,
		IPAddresses:  ips,
		EmailAddresses: emails,
		URIs:         uris,
	}

	if params.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		template.BasicConstraintsValid = true
	}

	// Get public key
	var pubKey interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, key)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, keyPEM, nil
}

// CSRParams holds parameters for generating a CSR.
type CSRParams struct {
	CommonName      string
	Organization    string
	OrganizationalUnit string
	Country         string
	Province        string
	Locality        string
	EmailAddress    string
	DNSNames        []string
	IPAddresses     []string
	KeyType         KeyType
	KeyBits         int
}

// GenerateCSR generates a CSR and private key.
func GenerateCSR(params CSRParams) (csrPEM string, keyPEM string, err error) {
	if params.KeyType == "" {
		params.KeyType = KeyTypeRSA
	}

	// Generate key
	key, keyStr, err := GenerateKey(params.KeyType, params.KeyBits)
	if err != nil {
		return "", "", err
	}
	keyPEM = keyStr

	// Build subject
	subject := pkix.Name{
		CommonName: params.CommonName,
	}
	if params.Organization != "" {
		subject.Organization = []string{params.Organization}
	}
	if params.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{params.OrganizationalUnit}
	}
	if params.Country != "" {
		subject.Country = []string{params.Country}
	}
	if params.Province != "" {
		subject.Province = []string{params.Province}
	}
	if params.Locality != "" {
		subject.Locality = []string{params.Locality}
	}

	// Parse IPs
	var ips []net.IP
	for _, ipStr := range params.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "", "", fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ips = append(ips, ip)
	}

	// Template
	template := &x509.CertificateRequest{
		Subject:     subject,
		DNSNames:    params.DNSNames,
		IPAddresses: ips,
	}

	// Get private key for signing
	var signer interface{}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		signer = k
	case *ecdsa.PrivateKey:
		signer = k
	case ed25519.PrivateKey:
		signer = k
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", "", fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return csrPEM, keyPEM, nil
}

// ConvertPEMToDER converts a PEM-encoded certificate to DER format (base64).
func ConvertPEMToDER(input string) (string, error) {
	block, _ := pem.Decode([]byte(input))
	if block == nil {
		return "", fmt.Errorf("input is not valid PEM")
	}
	return fmt.Sprintf("%x", block.Bytes), nil
}

// ConvertDERToPEM converts a DER-encoded certificate (hex string) to PEM.
func ConvertDERToPEM(hexStr string) (string, error) {
	der, err := decodeHex(hexStr)
	if err != nil {
		return "", fmt.Errorf("invalid hex string: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("failed to parse DER certificate: %w", err)
	}
	_ = cert
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(pemBytes), nil
}

// VerifyChain verifies a certificate against a pool of CA certificates.
func VerifyChain(certPEM string, caPEMs []string) error {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	for _, caPEM := range caPEMs {
		ca, err := ParseCertificate(caPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		roots.AddCert(ca)
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	return err
}

// CheckExpiry returns expiry information for a certificate.
func CheckExpiry(certPEM string) (notBefore time.Time, notAfter time.Time, isExpired bool, daysUntil int, err error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return time.Time{}, time.Time{}, false, 0, err
	}
	now := time.Now()
	return cert.NotBefore, cert.NotAfter, now.After(cert.NotAfter), int(cert.NotAfter.Sub(now).Hours() / 24), nil
}

// GetFingerprint returns the SHA-256 fingerprint of a certificate.
func GetFingerprint(certPEM string) (string, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return "", err
	}
	fp := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", fp[:]), nil
}

// ParseSANs parses a comma-separated SAN string into DNS names and IP addresses.
func ParseSANs(sans string) (dnsNames []string, ipAddresses []string) {
	if sans == "" {
		return nil, nil
	}
	for _, san := range strings.Split(sans, ",") {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if net.ParseIP(san) != nil {
			ipAddresses = append(ipAddresses, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	return dnsNames, ipAddresses
}
