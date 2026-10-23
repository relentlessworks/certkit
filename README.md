# certkit

A headless, agentic-first X.509 certificate toolkit service. No UI, no SDK — the API is the product.

## What It Does

certkit provides X.509 certificate operations over plain HTTP, designed for AI agents to drive:

- **Inspect** certificates and CSRs — extract all fields, fingerprints, SANs, key usage
- **Generate** self-signed certificates and CSAs — RSA, ECDSA, Ed25519
- **Verify** certificate chains against CA certificates
- **Check expiry** — days until expiry, expired status
- **Fingerprints** — SHA-256 fingerprints
- **Convert** between PEM and DER formats

## Quick Start

```bash
# Build
make build

# Run
./certkit

# Or with custom port
./certkit -port 9000
```

## API Endpoints

### `GET /help`
Returns the one-page operating manual.

### `GET /health`
Returns service health.

### `POST /v1/inspect`
Inspect a certificate. Send PEM as body.

### `POST /v1/generate`
Generate a self-signed certificate. Query params: `cn`, `org`, `sans`, `key_type`, `key_bits`, `days`, `is_ca`.

### `POST /v1/csr`
Generate a CSR. Query params: `cn`, `org`, `sans`, `key_type`, `key_bits`.

### `POST /v1/csr/inspect`
Inspect a CSR. Send PEM as body.

### `POST /v1/verify`
Verify a certificate against a CA. Body: cert PEM + `---CA---` separator + CA PEM.

### `POST /v1/expiry`
Check certificate expiry. Send PEM as body.

### `POST /v1/fingerprint`
Get SHA-256 fingerprint. Send PEM as body.

### `POST /v1/convert`
Convert between PEM and DER. Query param: `direction=pem-to-der|der-to-pem`.

## Response Format

- **Default:** Plain text, one `key=value` per line (grepable, token-cheap)
- **JSON:** Add `Accept: application/json` header or `?format=json`

## Error Format

Every 4xx response includes a hint:

```
error: missing required parameter: cn
hint: provide a common name, e.g. /v1/generate?cn=example.com
```

## Tech Stack

- **Language:** Go
- **Dependencies:** Zero external dependencies (stdlib only)
- **Build:** `CGO_ENABLED=0` — single static binary

## License

MIT
