package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/relentlessworks/certkit/internal/model"
)

// handleGenerate generates a self-signed certificate.
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"use POST /v1/generate?cn=example.com to generate a certificate")
		return
	}

	q := r.URL.Query()

	cn := q.Get("cn")
	if cn == "" {
		writeError(w, r, http.StatusBadRequest,
			"missing required parameter: cn",
			"provide a common name, e.g. /v1/generate?cn=example.com")
		return
	}

	keyType := model.KeyType(q.Get("key_type"))
	if keyType == "" {
		keyType = model.KeyTypeRSA
	}

	var keyBits int
	if v := q.Get("key_bits"); v != "" {
		bits, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("invalid key_bits value: %s", v),
				"key_bits must be an integer (e.g. 2048 for RSA, 256 for ECDSA)")
			return
		}
		keyBits = bits
	} else {
		if keyType == model.KeyTypeRSA {
			keyBits = 2048
		} else if keyType == model.KeyTypeECDSA {
			keyBits = 256
		}
	}

	var days int
	if v := q.Get("days"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("invalid days value: %s", v),
				"days must be an integer (e.g. 365)")
			return
		}
		days = d
	} else {
		days = 365
	}

	isCA := false
	if v := q.Get("is_ca"); v != "" {
		if v == "true" || v == "1" || v == "yes" {
			isCA = true
		}
	}

	var dnsNames, ipAddresses []string
	if sans := q.Get("sans"); sans != "" {
		dnsNames, ipAddresses = model.ParseSANs(sans)
	}

	params := model.CertParams{
		CommonName:      cn,
		Organization:    q.Get("org"),
		OrganizationalUnit: q.Get("ou"),
		Country:         q.Get("country"),
		Province:        q.Get("province"),
		Locality:        q.Get("locality"),
		EmailAddress:    q.Get("email"),
		DNSNames:        dnsNames,
		IPAddresses:     ipAddresses,
		KeyType:         keyType,
		KeyBits:         keyBits,
		Days:            days,
		IsCA:            isCA,
	}

	certPEM, keyPEM, err := model.GenerateSelfSigned(params)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("failed to generate certificate: %v", err),
			"check your parameters: cn is required, key_type must be rsa/ecdsa/ed25519")
		return
	}

	// Return both cert and key
	output := strings.TrimSpace(certPEM) + "\n\n" + strings.TrimSpace(keyPEM)
	writeOK(w, r, output)
}

// handleCSR generates a CSR.
func (s *Server) handleCSR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed,
			"only POST or GET is supported",
			"use POST /v1/csr?cn=example.com to generate a CSR")
		return
	}

	q := r.URL.Query()

	cn := q.Get("cn")
	if cn == "" {
		writeError(w, r, http.StatusBadRequest,
			"missing required parameter: cn",
			"provide a common name, e.g. /v1/csr?cn=example.com")
		return
	}

	keyType := model.KeyType(q.Get("key_type"))
	if keyType == "" {
		keyType = model.KeyTypeRSA
	}

	var keyBits int
	if v := q.Get("key_bits"); v != "" {
		bits, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, r, http.StatusBadRequest,
				fmt.Sprintf("invalid key_bits value: %s", v),
				"key_bits must be an integer (e.g. 2048 for RSA, 256 for ECDSA)")
			return
		}
		keyBits = bits
	} else {
		if keyType == model.KeyTypeRSA {
			keyBits = 2048
		} else if keyType == model.KeyTypeECDSA {
			keyBits = 256
		}
	}

	var dnsNames, ipAddresses []string
	if sans := q.Get("sans"); sans != "" {
		dnsNames, ipAddresses = model.ParseSANs(sans)
	}

	params := model.CSRParams{
		CommonName:      cn,
		Organization:    q.Get("org"),
		OrganizationalUnit: q.Get("ou"),
		Country:         q.Get("country"),
		Province:        q.Get("province"),
		Locality:        q.Get("locality"),
		DNSNames:        dnsNames,
		IPAddresses:     ipAddresses,
		KeyType:         keyType,
		KeyBits:         keyBits,
	}

	csrPEM, keyPEM, err := model.GenerateCSR(params)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError,
			fmt.Sprintf("failed to generate CSR: %v", err),
			"check your parameters: cn is required, key_type must be rsa/ecdsa/ed25519")
		return
	}

	output := strings.TrimSpace(csrPEM) + "\n\n" + strings.TrimSpace(keyPEM)
	writeOK(w, r, output)
}
