#ifndef NODE_KEY_H
#define NODE_KEY_H

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

    // Ownership contract:
    // - node_id, node_cert_pem and root_cert are NOT owned by this module (treated as const input views).
    //   They must remain valid for the duration of the call(s) that use them and are not freed here.
    // - node_key_der (generated here), csr_pem (generated here) and signature (generated here) ARE owned
    //   by this module and must be released with the corresponding free() helpers below.

    typedef struct {
        const char *node_id;        // Node ID string (not owned)
        unsigned char *node_key_der; // DER-encoded private key (owned)
        size_t node_key_der_len;
        const char *node_cert_pem;  // PEM-encoded certificate chain (not owned)
        size_t node_cert_pem_len;
    } node_key_t;

    typedef struct {
        const char *node_id; // Node ID string (not owned; typically same as node_key_t.node_id)
        char *csr_pem;       // PEM-encoded CSR (owned)
        size_t csr_pem_len;
    } node_csr_t;

    typedef struct {
        // ECDSA signature in DER format (owned). This is the ASN.1/DER-encoded SEQUENCE of (r, s).
        unsigned char *signature;
        size_t signature_len;
    } node_signature_t;

    typedef struct {
        // Single PEM bundle containing trusted roots and (optionally) intermediates. Not owned.
        // You may concatenate multiple PEM certs in this one buffer.
        const char *ca_bundle_pem;
        size_t ca_bundle_pem_len;
    } node_root_trust_t;

    // generates a new key pair into nk->node_key_der
    esp_err_t node_key_generate(node_key_t *nk);
    // generates a new CSR for nk->node_key_der with subject CN=node_id
    esp_err_t node_key_generate_csr(const node_key_t *nk, node_csr_t *csr);
    // signs binary data with nk->node_key_der
    esp_err_t node_key_sign(const node_key_t *nk, node_signature_t *sig, const uint8_t *data, size_t data_len);
    // verifies binary data signed by the private key in nk->node_key_der (using public part)
    esp_err_t node_key_verify_signature(const node_key_t *nk, const uint8_t *data, size_t data_len, const node_signature_t *sig);

    // verifies that nk->node_cert_pem chains up to a trusted CA in rts->ca_bundle_pem
    esp_err_t node_key_verify_root_trust(const node_key_t *nk, const node_root_trust_t *rts);
    // verifies data signed by a CA/private key present in rts->ca_bundle_pem using its public key
    esp_err_t node_key_verify_root_signature(const node_root_trust_t *rts, const uint8_t *data, size_t data_len, const node_signature_t *sig);

    // Helpers for decoupled storage and transport
    // - Set/replace the private key DER (makes an internal copy and validates it parses)
    esp_err_t node_key_set_key_der(node_key_t *nk, const uint8_t *der, size_t der_len);
    // - Set/replace the certificate chain PEM view (not owned). Validates parseability.
    esp_err_t node_key_set_cert_pem(node_key_t *nk, const char *pem, size_t pem_len);
    // - Export public key in PEM format derived from current private key
    esp_err_t node_key_export_public_pem(const node_key_t *nk, char **out_pem, size_t *out_pem_len);
    // - Convert signature to Base64 (allocates a null-terminated C string)
    esp_err_t node_signature_to_base64(const node_signature_t *sig, char **out_b64, size_t *out_b64_len);
    // - Parse Base64 into signature (replaces owned buffer)
    esp_err_t node_signature_from_base64(node_signature_t *sig, const char *b64, size_t b64_len);

    // frees owned buffers in node_key_t (does not free node_id or node_cert_pem)
    esp_err_t node_key_free(node_key_t *nk);
    // frees csr_pem in node_csr_t (does not free node_id)
    esp_err_t node_csr_free(node_csr_t *csr);
    // frees signature buffer
    esp_err_t node_signature_free(node_signature_t *sig);
    // clears pointers in node_root_trust_t (does not free ca_bundle_pem)
    esp_err_t node_root_trust_free(node_root_trust_t *rts);

#ifdef __cplusplus
}
#endif

#endif // NODE_KEY_H