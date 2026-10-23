package model

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseCertificate parses a PEM or DER encoded X.509 certificate.
func ParseCertificate(input string) (*x509.Certificate, error) {
	// Try PEM first
	block, _ := pem.Decode([]byte(input))
	if block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected CERTIFICATE PEM block, got %s", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		return cert, nil
	}

	// Try DER
	cert, err := x509.ParseCertificate([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("input is not valid PEM or DER certificate: %w", err)
	}
	return cert, nil
}
