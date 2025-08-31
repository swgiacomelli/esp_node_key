// Keep tests lean and self-contained for the component build. Advanced CA-chain tests
// live in the standalone test app under tests/node_key_app.

#if defined(UNITY_INCLUDE_CONFIG_H)

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "unity.h"
#include "node_key.h"

static void test_keygen_sign_verify_and_base64_impl(void)
{
    node_key_t nk = (node_key_t){0};
    nk.node_id = "TEST-NODE";

    TEST_ASSERT_EQUAL(ESP_OK, node_key_generate(&nk));
    TEST_ASSERT_NOT_NULL(nk.node_key_der);
    TEST_ASSERT_TRUE(nk.node_key_der_len > 0);

    const uint8_t data[] = "hello world";
    node_signature_t sig = (node_signature_t){0};
    TEST_ASSERT_EQUAL(ESP_OK, node_key_sign(&nk, &sig, data, sizeof(data) - 1));
    TEST_ASSERT_NOT_NULL(sig.signature);
    TEST_ASSERT_TRUE(sig.signature_len > 0);

    TEST_ASSERT_EQUAL(ESP_OK, node_key_verify_signature(&nk, data, sizeof(data) - 1, &sig));

    // Base64 round trip
    char *b64 = NULL; size_t b64_len = 0;
    TEST_ASSERT_EQUAL(ESP_OK, node_signature_to_base64(&sig, &b64, &b64_len));
    TEST_ASSERT_NOT_NULL(b64);
    TEST_ASSERT_TRUE(b64_len > 0);

    node_signature_t sig2 = (node_signature_t){0};
    TEST_ASSERT_EQUAL(ESP_OK, node_signature_from_base64(&sig2, b64, b64_len));
    TEST_ASSERT_EQUAL(sig.signature_len, sig2.signature_len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig.signature, sig2.signature, sig.signature_len);

    free(b64);
    node_signature_free(&sig2);
    node_signature_free(&sig);
    node_key_free(&nk);
}

static void test_public_key_export_and_csr_impl(void)
{
    node_key_t nk = (node_key_t){0};
    nk.node_id = "TEST-NODE";
    TEST_ASSERT_EQUAL(ESP_OK, node_key_generate(&nk));

    char *pub_pem = NULL; size_t pub_len = 0;
    TEST_ASSERT_EQUAL(ESP_OK, node_key_export_public_pem(&nk, &pub_pem, &pub_len));
    TEST_ASSERT_NOT_NULL(pub_pem);
    TEST_ASSERT_TRUE(pub_len > 0);
    TEST_ASSERT_NOT_NULL(strstr(pub_pem, "BEGIN PUBLIC KEY"));

    node_csr_t csr = (node_csr_t){0};
    csr.node_id = nk.node_id;
    TEST_ASSERT_EQUAL(ESP_OK, node_key_generate_csr(&nk, &csr));
    TEST_ASSERT_NOT_NULL(csr.csr_pem);
    TEST_ASSERT_TRUE(csr.csr_pem_len > 0);
    TEST_ASSERT_NOT_NULL(strstr(csr.csr_pem, "BEGIN CERTIFICATE REQUEST"));

    free(pub_pem);
    node_csr_free(&csr);
    node_key_free(&nk);
}

TEST_CASE("node_key: keygen/sign/verify + base64", "[node_key]")
{
    test_keygen_sign_verify_and_base64_impl();
}

TEST_CASE("node_key: public key export + CSR", "[node_key]")
{
    test_public_key_export_and_csr_impl();
}

#endif // UNITY_INCLUDE_CONFIG_H