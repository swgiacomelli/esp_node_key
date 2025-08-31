#include "node_key.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "esp_check.h"

#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"

static void secure_free(void *ptr, size_t len)
{
    if (ptr && len) {
        mbedtls_platform_zeroize(ptr, len);
    }
    free(ptr);
}

static esp_err_t parse_der(const unsigned char *der, size_t len, mbedtls_pk_context *pk)
{
    if (!der || len == 0 || !pk) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_pk_init(pk);
    int ret = mbedtls_pk_parse_key(pk, der, len, NULL, 0, NULL, NULL);
    if (ret != 0) {
        mbedtls_pk_free(pk);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t parse_pem_chain(const char *pem, size_t len, mbedtls_x509_crt *crt)
{
    if (!pem || len == 0 || !crt) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_x509_crt_init(crt);

    int ret;
    if (pem[len - 1] == '\0') {
        ret = mbedtls_x509_crt_parse(crt, (const unsigned char *)pem, len);
    } else {
        // Ensure null-terminated PEM by copying to a temporary buffer
        size_t tmp_len = len + 1;
        unsigned char *tmp = (unsigned char *)malloc(tmp_len);
        if (!tmp) {
            mbedtls_x509_crt_free(crt);
            return ESP_ERR_NO_MEM;
        }
        memcpy(tmp, pem, len);
        tmp[len] = '\0';
        ret = mbedtls_x509_crt_parse(crt, tmp, tmp_len);
        // tmp contains public material; zeroizing isn't strictly required but harmless
        secure_free(tmp, tmp_len);
    }

    if (ret != 0) {
        mbedtls_x509_crt_free(crt);
        return ESP_FAIL;
    }

    return ESP_OK;
}


esp_err_t node_key_free(node_key_t *nk)
{
    if (!nk) {
        return ESP_ERR_INVALID_ARG;
    }
    if (nk->node_key_der) {
        secure_free(nk->node_key_der, nk->node_key_der_len);
        nk->node_key_der = NULL;
        nk->node_key_der_len = 0;
    }
    // node_id and node_cert_pem are not owned; just clear lengths/pointers if needed
    nk->node_cert_pem_len = 0;
    return ESP_OK;
}

esp_err_t node_csr_free(node_csr_t *csr)
{
    if (!csr) {
        return ESP_ERR_INVALID_ARG;
    }
    if (csr->csr_pem) {
        secure_free(csr->csr_pem, csr->csr_pem_len);
        csr->csr_pem = NULL;
        csr->csr_pem_len = 0;
    }
    return ESP_OK;
}

esp_err_t node_signature_free(node_signature_t *sig)
{
    if (!sig) {
        return ESP_ERR_INVALID_ARG;
    }

    if (sig->signature) {
        secure_free(sig->signature, sig->signature_len);
        sig->signature = NULL;
        sig->signature_len = 0;
    }
    return ESP_OK;
}

esp_err_t node_root_trust_free(node_root_trust_t *rts)
{
    if (!rts) {
        return ESP_ERR_INVALID_ARG;
    }
    // CA bundle is not owned; do not free
    rts->ca_bundle_pem_len = 0;
    return ESP_OK;
}

esp_err_t node_key_generate(node_key_t *nk)
{
    if (!nk) {
        return ESP_ERR_INVALID_ARG;
    }

    // Generate ECDSA P-256
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_context ent;
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ctr_drbg_init(&drbg);

    const char *pers = nk->node_id ? nk->node_id : "node-key";
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }
    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
                               mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    // Export to DER
    unsigned char buf[1600];
    int der_len = mbedtls_pk_write_key_der(&pk, buf, sizeof(buf));
    if (der_len <= 0)
    {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_FAIL;
    }

    if (nk->node_key_der) {
        secure_free(nk->node_key_der, nk->node_key_der_len);
        nk->node_key_der = NULL;
        nk->node_key_der_len = 0;
    }

    nk->node_key_der = (unsigned char *)malloc((size_t)der_len);
    if (!nk->node_key_der) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_ERR_NO_MEM;
    }

    memcpy(nk->node_key_der, buf + sizeof(buf) - (size_t)der_len, (size_t)der_len);
    nk->node_key_der_len = (size_t)der_len;

    mbedtls_platform_zeroize(buf, sizeof(buf));
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);

    return ESP_OK;
}

esp_err_t node_key_generate_csr(const node_key_t *nk, node_csr_t *csr)
{
    if (!nk || !csr) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_pk_context pk;
    if (parse_der(nk->node_key_der, nk->node_key_der_len, &pk) != ESP_OK) {
        return ESP_FAIL;
    }

    mbedtls_x509write_csr req;
    mbedtls_x509write_csr_init(&req);
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, &pk);
    // Subject: CN=NODE_ID
    char subj[128];
    snprintf(subj, sizeof subj, "CN=%s", nk->node_id ? nk->node_id : "");
    mbedtls_x509write_csr_set_subject_name(&req, subj);

    unsigned char buf[2048];
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_context ent;
    mbedtls_entropy_init(&ent);
    const char *pers = "csr";
    int ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_x509write_csr_free(&req);
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_FAIL;
    }

    int r = mbedtls_x509write_csr_pem(&req, buf, sizeof(buf),
                                      mbedtls_ctr_drbg_random, &drbg);
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    if (r != 0) {
        return ESP_FAIL;
    }

    size_t pem_len = strlen((char *)buf) + 1;

    if (csr->csr_pem) {
        secure_free(csr->csr_pem, csr->csr_pem_len);
        csr->csr_pem = NULL;
    }

    csr->csr_pem = (char *)malloc(pem_len);
    if (!csr->csr_pem) {
        return ESP_ERR_NO_MEM;
    }

    memcpy(csr->csr_pem, buf, pem_len);
    csr->csr_pem_len = pem_len;

    return ESP_OK;
}

esp_err_t node_key_sign(const node_key_t *nk, node_signature_t *sig, const uint8_t* data, size_t data_len)
{
    if (!nk || !data || data_len == 0 || !sig) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_pk_context pk;
    if (parse_der(nk->node_key_der, nk->node_key_der_len, &pk) != ESP_OK) {
        return ESP_FAIL;
    }

    // Sign the data using ECDSA with SHA-256
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char *)data, data_len, hash, 0);

    mbedtls_entropy_context ent;
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ctr_drbg_init(&drbg);
    const char *pers = nk->node_id ? nk->node_id : "node-sign";
    int seed_ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                         (const unsigned char *)pers, strlen(pers));
    if (seed_ret != 0) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_FAIL;
    }

    unsigned char signature[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    int ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                              signature, sizeof(signature), &sig_len,
                              mbedtls_ctr_drbg_random, &drbg);
    if (ret != 0) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_FAIL;
    }

    if (sig->signature) {
        secure_free(sig->signature, sig->signature_len);
        sig->signature = NULL;
        sig->signature_len = 0;
    }

    sig->signature = (unsigned char *)malloc(sig_len);
    if (!sig->signature) {
        mbedtls_pk_free(&pk);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&ent);
        return ESP_ERR_NO_MEM;
    }

    memcpy(sig->signature, signature, sig_len);
    sig->signature_len = sig_len;

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);

    return ESP_OK;
}

esp_err_t node_key_verify_signature(const node_key_t *nk, const uint8_t* data, size_t data_len, const node_signature_t *sig)
{
    if (!nk || !data || data_len == 0 || !sig || !sig->signature || sig->signature_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_pk_context pk;
    if (parse_der(nk->node_key_der, nk->node_key_der_len, &pk) != ESP_OK) {
        return ESP_FAIL;
    }

    // Verify the signature using ECDSA with SHA-256
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char *)data, data_len, hash, 0);

    int ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                 (const unsigned char *)sig->signature, sig->signature_len);
    mbedtls_pk_free(&pk);
    if (ret != 0) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t node_key_verify_root_trust(const node_key_t *nk, const node_root_trust_t *rts)
{
    if (!nk || !nk->node_cert_pem || nk->node_cert_pem_len == 0 || !rts || !rts->ca_bundle_pem || rts->ca_bundle_pem_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_x509_crt crt;
    if (parse_pem_chain(nk->node_cert_pem, nk->node_cert_pem_len, &crt) != ESP_OK) {
        return ESP_FAIL;
    }

    mbedtls_x509_crt ca_bundle;
    if (parse_pem_chain(rts->ca_bundle_pem, rts->ca_bundle_pem_len, &ca_bundle) != ESP_OK) {
        mbedtls_x509_crt_free(&crt);
        return ESP_FAIL;
    }

    uint32_t flags = 0;
    // Verify device certificate chain against the CA bundle as trust store; no CRL provided
    int ret = mbedtls_x509_crt_verify(&crt, &ca_bundle, NULL,
                                      NULL, &flags, NULL, NULL);
    mbedtls_x509_crt_free(&crt);
    mbedtls_x509_crt_free(&ca_bundle);
    if (ret != 0 || flags != 0) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t node_key_verify_root_signature(const node_root_trust_t *rts, const uint8_t *data, size_t data_len, const node_signature_t *sig)
{
    if (!rts || !rts->ca_bundle_pem || rts->ca_bundle_pem_len == 0 || !data || data_len == 0 || !sig || !sig->signature || sig->signature_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Parse CA bundle once; will use it both as trust anchors and possible signers
    mbedtls_x509_crt ca_bundle;
    if (parse_pem_chain(rts->ca_bundle_pem, rts->ca_bundle_pem_len, &ca_bundle) != ESP_OK) {
        return ESP_FAIL;
    }

    // Strategy: iterate certificates in bundle and pick a signer whose chain verifies against the bundle.
    // Then verify the signature with that cert's public key.
    mbedtls_x509_crt *candidate = &ca_bundle;
    esp_err_t result = ESP_FAIL;
    for (mbedtls_x509_crt *cur = &ca_bundle; cur != NULL; cur = cur->next) {
        uint32_t flags = 0;
        // Verify cur against the bundle (trust = bundle); no CRL provided
        int v = mbedtls_x509_crt_verify(cur, &ca_bundle, NULL, NULL, &flags, NULL, NULL);
        if (v == 0 && flags == 0) {
            candidate = cur;
            // Prefer certificates with suitable key usages: digitalSignature or keyCertSign
            int ku_ok = 0;
            if (mbedtls_x509_crt_check_key_usage(cur, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0) {
                ku_ok = 1;
            }
            if (mbedtls_x509_crt_check_key_usage(cur, MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0) {
                ku_ok = 1;
            }
            if (ku_ok) {
                result = ESP_OK;
                break;
            }
        }
    }

    if (result != ESP_OK) {
        // No valid signer found
        mbedtls_x509_crt_free(&ca_bundle);
        return ESP_FAIL;
    }

    // Verify the signature using ECDSA with SHA-256
    unsigned char hash[32];
    mbedtls_sha256((const unsigned char *)data, data_len, hash, 0);

    int ret = mbedtls_pk_verify(&candidate->pk, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                 (const unsigned char *)sig->signature, sig->signature_len);
    mbedtls_x509_crt_free(&ca_bundle);
    if (ret != 0) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t node_key_set_key_der(node_key_t *nk, const uint8_t *der, size_t der_len)
{
    if (!nk || !der || der_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    // Validate it parses
    mbedtls_pk_context pk;
    if (parse_der(der, der_len, &pk) != ESP_OK) {
        return ESP_FAIL;
    }
    mbedtls_pk_free(&pk);

    // Replace current DER
    if (nk->node_key_der) {
        secure_free(nk->node_key_der, nk->node_key_der_len);
        nk->node_key_der = NULL;
        nk->node_key_der_len = 0;
    }
    nk->node_key_der = (unsigned char *)malloc(der_len);
    if (!nk->node_key_der) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(nk->node_key_der, der, der_len);
    nk->node_key_der_len = der_len;
    return ESP_OK;
}

esp_err_t node_key_set_cert_pem(node_key_t *nk, const char *pem, size_t pem_len)
{
    if (!nk || !pem || pem_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    // Validate parseability (no ownership; just a view)
    mbedtls_x509_crt crt;
    if (parse_pem_chain(pem, pem_len, &crt) != ESP_OK) {
        return ESP_FAIL;
    }
    mbedtls_x509_crt_free(&crt);
    nk->node_cert_pem = pem;
    nk->node_cert_pem_len = pem_len;
    return ESP_OK;
}

esp_err_t node_key_export_public_pem(const node_key_t *nk, char **out_pem, size_t *out_pem_len)
{
    if (!nk || !nk->node_key_der || nk->node_key_der_len == 0 || !out_pem || !out_pem_len) {
        return ESP_ERR_INVALID_ARG;
    }
    mbedtls_pk_context pk;
    if (parse_der(nk->node_key_der, nk->node_key_der_len, &pk) != ESP_OK) {
        return ESP_FAIL;
    }
    unsigned char buf[800];
    int ret = mbedtls_pk_write_pubkey_pem(&pk, buf, sizeof(buf));
    mbedtls_pk_free(&pk);
    if (ret != 0) {
        return ESP_FAIL;
    }
    // For safety, compute actual length as C string
    size_t pem_len = strnlen((const char *)buf, sizeof(buf));
    if (pem_len == sizeof(buf)) {
        return ESP_FAIL;
    }
    pem_len += 1; // include NUL
    *out_pem = (char *)malloc(pem_len);
    if (!*out_pem) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(*out_pem, buf, pem_len);
    *out_pem_len = pem_len;
    return ESP_OK;
}

esp_err_t node_signature_to_base64(const node_signature_t *sig, char **out_b64, size_t *out_b64_len)
{
    if (!sig || !sig->signature || sig->signature_len == 0 || !out_b64 || !out_b64_len) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t olen = 0;
    // First, query length
    int ret = mbedtls_base64_encode(NULL, 0, &olen, sig->signature, sig->signature_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return ESP_FAIL;
    }
    // Allocate +1 for NUL
    *out_b64 = (char *)malloc(olen + 1);
    if (!*out_b64) {
        return ESP_ERR_NO_MEM;
    }
    ret = mbedtls_base64_encode((unsigned char *)*out_b64, olen, &olen, sig->signature, sig->signature_len);
    if (ret != 0) {
        free(*out_b64);
        *out_b64 = NULL;
        return ESP_FAIL;
    }
    (*out_b64)[olen] = '\0';
    *out_b64_len = olen + 1;
    return ESP_OK;
}

esp_err_t node_signature_from_base64(node_signature_t *sig, const char *b64, size_t b64_len)
{
    if (!sig || !b64 || b64_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t olen = 0;
    int ret = mbedtls_base64_decode(NULL, 0, &olen, (const unsigned char *)b64, b64_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return ESP_FAIL;
    }
    unsigned char *buf = (unsigned char *)malloc(olen);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }
    ret = mbedtls_base64_decode(buf, olen, &olen, (const unsigned char *)b64, b64_len);
    if (ret != 0) {
        free(buf);
        return ESP_FAIL;
    }
    if (sig->signature) {
        secure_free(sig->signature, sig->signature_len);
        sig->signature = NULL;
        sig->signature_len = 0;
    }
    sig->signature = buf;
    sig->signature_len = olen;
    return ESP_OK;
}

 