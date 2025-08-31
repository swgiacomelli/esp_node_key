#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "node_key.h"

static const char *TAG = "node_key_example";

void app_main(void)
{
    node_key_t nk = {0};
    nk.node_id = "EXAMPLE-NODE";

    if (node_key_generate(&nk) != ESP_OK) {
        ESP_LOGE(TAG, "keygen failed");
        return;
    }

    const uint8_t msg[] = "hello from node_key";
    node_signature_t sig = {0};
    if (node_key_sign(&nk, &sig, msg, sizeof(msg) - 1) != ESP_OK) {
        ESP_LOGE(TAG, "sign failed");
        node_key_free(&nk);
        return;
    }
    ESP_LOGI(TAG, "signature len: %u", (unsigned)sig.signature_len);

    if (node_key_verify_signature(&nk, msg, sizeof(msg) - 1, &sig) != ESP_OK) {
        ESP_LOGE(TAG, "verify failed");
    } else {
        ESP_LOGI(TAG, "verify ok");
    }

    unsigned char *pub_der = NULL; size_t pub_len = 0;
    if (node_key_export_public_der(&nk, &pub_der, &pub_len) == ESP_OK) {
        ESP_LOGI(TAG, "public key DER len: %u", (unsigned)pub_len);
        free(pub_der);
    }

    node_csr_t csr = { .node_id = nk.node_id };
    if (node_key_generate_csr_der(&nk, &csr) == ESP_OK) {
        ESP_LOGI(TAG, "CSR DER len: %u", (unsigned)csr.csr_der_len);
        node_csr_free(&csr);
    }

    node_signature_free(&sig);
    node_key_free(&nk);
}
