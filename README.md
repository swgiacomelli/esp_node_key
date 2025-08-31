# node_key (ESP-IDF component)

Lightweight node identity key management for ESP-IDF using mbedTLS:
- Generate an EC (P-256) private key (DER)
- Create a CSR (DER)
- Sign/verify binary data (ECDSA + SHA-256)
- Export public key (DER, SubjectPublicKeyInfo)
- Base64 helpers for signatures
- Verify device certificate (DER) against a CA list (DER)
- Verify a signature by any cert in a CA list that chains to an anchor in the same list

License: ISC (see LICENSE)

## Requirements
- ESP-IDF v5.x+
- mbedTLS (bundled with ESP-IDF)

## Install (from Git)
Repo: https://github.com/swgiacomelli/esp_node_key

Two simple ways:
- Submodule: add to your project at `components/node_key`.
- External dir: keep it anywhere and point EXTRA_COMPONENT_DIRS to its parent.

Submodule example (PowerShell):
```
git submodule add https://github.com/swgiacomelli/esp_node_key components/node_key
```

External dir build example:
```
idf.py -DEXTRA_COMPONENT_DIRS="C:/path/to/esp_node_key" build
```

## Build
Nothing special—CMake lists `node_key.c` and public headers under `include/`.

## Public API
See `include/node_key.h`. Highlights:
- node_key_generate(node_key_t*)
- node_key_generate_csr_der(const node_key_t*, node_csr_t*)
- node_key_sign(const node_key_t*, node_signature_t*, const uint8_t*, size_t)
- node_key_verify_signature(const node_key_t*, const uint8_t*, size_t, const node_signature_t*)
- node_key_verify_root_trust(const node_key_t*, const node_root_trust_t*)
- node_key_verify_root_signature(const node_root_trust_t*, const uint8_t*, size_t, const node_signature_t*)
- node_key_set_key_der(node_key_t*, const uint8_t*, size_t)
- node_key_set_cert_der(node_key_t*, const unsigned char*, size_t)
- node_key_export_public_der(const node_key_t*, unsigned char**, size_t*)
- node_signature_to_base64/from_base64
- Free helpers: node_key_free, node_csr_free, node_signature_free, node_root_trust_free

Ownership: DER key, CSR DER, and signature buffers are owned by the struct and must be freed with the provided helpers. DER inputs (device cert, CA list) and node_id are views (not owned).

## Example
A minimal example is provided in `examples/basic` that generates a key, signs data, verifies it, and creates a CSR.

Run (PowerShell):
- Use the ESP-IDF PowerShell, then from the cloned repo root:
```
idf.py -C "examples/basic" -DIDF_TARGET=esp32s3 build
idf.py -C "examples/basic" -p COM5 -b 921600 flash monitor
```

Adjust COM port and target as needed.