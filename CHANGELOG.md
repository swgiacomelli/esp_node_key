# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 — 2025-08-31

Breaking change: migrate public APIs from PEM to DER for CSRs, device certificate, CA trust inputs, and public key export.

- Switched to DER-only interfaces:
  - CSR: `node_key_generate_csr_der(const node_key_t*, node_csr_t*)` returns DER in `node_csr_t.csr_der`.
  - Device certificate: `node_key_set_cert_der(node_key_t*, const unsigned char*, size_t)` (view only).
  - CA trust: `node_root_trust_t` now contains arrays of DER cert pointers and lengths.
  - Public key export: `node_key_export_public_der(const node_key_t*, unsigned char**, size_t*)`.
- Kept signatures as DER (ASN.1 SEQUENCE of r,s). Base64 helpers unchanged.
- Updated tests and example to DER usage.
- Docs updated. Version bumped to 0.2.0.

Migration notes:
- Replace previous PEM-based functions:
  - `node_key_generate_csr(...)` -> `node_key_generate_csr_der(...)`.
  - `node_key_export_public_pem(...)` -> `node_key_export_public_der(...)`.
  - `node_key_set_cert_pem(...)` -> `node_key_set_cert_der(...)`.
- Use `node_root_trust_t` DER arrays instead of concatenated PEM bundle.
- If you have PEM material, convert to DER before calling APIs (e.g., parse with mbedTLS and re-encode as DER).

## 0.1.x — 2025-08-xx

- Initial releases with PEM-centric CSR, certificate, and CA bundle handling.
- ECDSA key generation, sign/verify, and Base64 helpers.