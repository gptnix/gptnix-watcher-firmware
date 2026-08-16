/**
 * GPTNiX Watcher QR pairing decoder/parser foundation.
 *
 * See app_gptnix_qr_pair.h for the public contract and
 * docs/GPTNIX_QR_PAIRING_CONTRACT_V1.md for the QR payload contract.
 *
 * This module owns only QR decode/parser resources (a module-owned quirc
 * context and two bounded, preallocated scratch buffers). It never touches
 * the canonical SSCMA client — no camera init, sampling, model invocation,
 * sensor selection, or callback (re-)registration of any kind. The
 * canonical camera owner (task_flow_module/tf_module_ai_camera.c) is
 * untouched by this file. Runtime camera/backend wiring is a separate
 * follow-up task.
 */
#include "app_gptnix_qr_pair.h"
#include "sdkconfig.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "GPTNIX_QR_PAIR";

void app_gptnix_qr_pair_payload_clear(gptnix_qr_pair_payload_t *payload)
{
    if (payload == NULL) {
        return;
    }
    mbedtls_platform_zeroize(payload, sizeof(*payload));
}

#if CONFIG_GPTNIX_QR_PAIRING

#include <stdlib.h>

#include "esp_heap_caps.h"
#include "mbedtls/base64.h"
#include "cJSON.h"
#include "esp_jpeg_dec.h"
#include "quirc.h"
#include "isp.h"

#define GPTNIX_QR_IMAGE_WIDTH       (240)
#define GPTNIX_QR_IMAGE_HEIGHT      (240)
#define GPTNIX_QR_JPEG_MAX_BYTES    (49152) /* 48 KiB, matches the proven examples/qrcode_reader ceiling */
#define GPTNIX_QR_BASE64_MAX_BYTES  (65536)
#define GPTNIX_QR_PAYLOAD_MAX_BYTES (512)
#define GPTNIX_QR_RGB565_BYTES      (GPTNIX_QR_IMAGE_WIDTH * GPTNIX_QR_IMAGE_HEIGHT * 2) /* 115200 */

static bool s_initialized = false;
static struct quirc *s_quirc = NULL;
static uint8_t *s_jpeg_buf = NULL;   /* GPTNIX_QR_JPEG_MAX_BYTES, decoded (base64->binary) JPEG bytes */
static uint8_t *s_rgb565_buf = NULL; /* GPTNIX_QR_RGB565_BYTES, 16-byte aligned JPEG decode output */

/* Unwinds exactly the resources already acquired at the point of a partial
 * init failure; never touches a resource that was never acquired. */
static void s_unwind_partial_init(bool have_rgb565_buf, bool have_jpeg_buf, bool have_quirc)
{
    if (have_rgb565_buf && s_rgb565_buf != NULL) {
        free(s_rgb565_buf);
        s_rgb565_buf = NULL;
    }
    if (have_jpeg_buf && s_jpeg_buf != NULL) {
        free(s_jpeg_buf);
        s_jpeg_buf = NULL;
    }
    if (have_quirc && s_quirc != NULL) {
        quirc_destroy(s_quirc);
        s_quirc = NULL;
    }
}

esp_err_t app_gptnix_qr_pair_init(void)
{
    if (s_initialized) {
        return ESP_OK;
    }

    s_quirc = quirc_new();
    if (s_quirc == NULL) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] init: no_memory");
        return ESP_ERR_NO_MEM;
    }

    if (quirc_resize(s_quirc, GPTNIX_QR_IMAGE_WIDTH, GPTNIX_QR_IMAGE_HEIGHT) != 0) {
        s_unwind_partial_init(false, false, true);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] init: no_memory");
        return ESP_ERR_NO_MEM;
    }

    s_jpeg_buf = (uint8_t *)heap_caps_malloc(GPTNIX_QR_JPEG_MAX_BYTES, MALLOC_CAP_SPIRAM);
    if (s_jpeg_buf == NULL) {
        s_unwind_partial_init(false, false, true);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] init: no_memory");
        return ESP_ERR_NO_MEM;
    }

    s_rgb565_buf = (uint8_t *)heap_caps_aligned_alloc(16, GPTNIX_QR_RGB565_BYTES, MALLOC_CAP_SPIRAM);
    if (s_rgb565_buf == NULL) {
        s_unwind_partial_init(false, true, true);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] init: no_memory");
        return ESP_ERR_NO_MEM;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "[GPTNIX_QR_PAIR] init: ready");
    return ESP_OK;
}

void app_gptnix_qr_pair_deinit(void)
{
    if (!s_initialized) {
        return;
    }
    s_unwind_partial_init(true, true, true);
    s_initialized = false;
}

gptnix_qr_pair_result_t app_gptnix_qr_pair_decode_base64_jpeg(
    const char *image_b64,
    size_t image_b64_len,
    gptnix_qr_pair_payload_t *out_payload)
{
    if (out_payload != NULL) {
        app_gptnix_qr_pair_payload_clear(out_payload);
    }

    if (image_b64 == NULL || out_payload == NULL || image_b64_len == 0) {
        return GPTNIX_QR_PAIR_RESULT_INVALID_ARGUMENT;
    }

    if (!s_initialized) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: not_initialized");
        return GPTNIX_QR_PAIR_RESULT_NOT_INITIALIZED;
    }

    if (image_b64_len > GPTNIX_QR_BASE64_MAX_BYTES) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_too_large");
        return GPTNIX_QR_PAIR_RESULT_IMAGE_TOO_LARGE;
    }

    size_t jpeg_len = 0;
    int b64_ret = mbedtls_base64_decode(
        s_jpeg_buf, GPTNIX_QR_JPEG_MAX_BYTES, &jpeg_len,
        (const unsigned char *)image_b64, image_b64_len);
    if (b64_ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_too_large");
        return GPTNIX_QR_PAIR_RESULT_IMAGE_TOO_LARGE;
    }
    if (b64_ret != 0 || jpeg_len == 0) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
        return GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
    }

    jpeg_dec_config_t jpeg_config = {
        .output_type = JPEG_RAW_TYPE_RGB565_BE,
        .rotate = JPEG_ROTATE_0D,
    };
    jpeg_dec_handle_t jpeg_dec = jpeg_dec_open(&jpeg_config);
    if (jpeg_dec == NULL) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: no_memory");
        return GPTNIX_QR_PAIR_RESULT_NO_MEMORY;
    }

    jpeg_dec_io_t jpeg_io;
    memset(&jpeg_io, 0, sizeof(jpeg_io));
    jpeg_dec_header_info_t jpeg_info;
    memset(&jpeg_info, 0, sizeof(jpeg_info));

    jpeg_io.inbuf = s_jpeg_buf;
    jpeg_io.inbuf_len = (int)jpeg_len;

    jpeg_error_t jret = jpeg_dec_parse_header(jpeg_dec, &jpeg_io, &jpeg_info);
    if (jret != JPEG_ERR_OK) {
        jpeg_dec_close(jpeg_dec);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
        return GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
    }

    /* The fixed-size s_rgb565_buf is sized for exactly 240x240. Reject any
     * other JPEG dimensions BEFORE calling jpeg_dec_process, which would
     * otherwise write width*height*2 bytes into that fixed buffer. */
    if (jpeg_info.width != GPTNIX_QR_IMAGE_WIDTH || jpeg_info.height != GPTNIX_QR_IMAGE_HEIGHT) {
        jpeg_dec_close(jpeg_dec);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: unsupported_dimensions");
        return GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS;
    }

    jpeg_io.outbuf = s_rgb565_buf;
    int inbuf_consumed = jpeg_io.inbuf_len - jpeg_io.inbuf_remain;
    jpeg_io.inbuf = s_jpeg_buf + inbuf_consumed;
    jpeg_io.inbuf_len = jpeg_io.inbuf_remain;

    jret = jpeg_dec_process(jpeg_dec, &jpeg_io);
    jpeg_dec_close(jpeg_dec);
    if (jret != JPEG_ERR_OK) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
        return GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
    }

    int qw = 0, qh = 0;
    uint8_t *qbuf = quirc_begin(s_quirc, &qw, &qh);
    if (qbuf == NULL || qw != GPTNIX_QR_IMAGE_WIDTH || qh != GPTNIX_QR_IMAGE_HEIGHT) {
        if (qbuf != NULL) {
            /* quirc_begin/quirc_end must stay paired on every path once
             * quirc_begin has been called. */
            quirc_end(s_quirc);
        }
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: unsupported_dimensions");
        return GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS;
    }

    /* Same orientation behavior as the proven examples/qrcode_reader path. */
    rgb565_to_gray(qbuf, s_rgb565_buf,
                    GPTNIX_QR_IMAGE_HEIGHT, GPTNIX_QR_IMAGE_WIDTH,
                    GPTNIX_QR_IMAGE_HEIGHT, GPTNIX_QR_IMAGE_WIDTH,
                    ROTATION_UP, true);

    quirc_end(s_quirc);

    int count = quirc_count(s_quirc);
    if (count == 0) {
        ESP_LOGI(TAG, "[GPTNIX_QR_PAIR] decode: no_code");
        return GPTNIX_QR_PAIR_RESULT_NO_CODE;
    }
    if (count > 1) {
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: ambiguous");
        return GPTNIX_QR_PAIR_RESULT_AMBIGUOUS;
    }

    struct quirc_code code;
    struct quirc_data data;
    quirc_extract(s_quirc, 0, &code);
    quirc_decode_error_t qerr = quirc_decode(&code, &data);
    mbedtls_platform_zeroize(&code, sizeof(code));

    if (qerr != QUIRC_SUCCESS) {
        mbedtls_platform_zeroize(&data, sizeof(data));
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
        return GPTNIX_QR_PAIR_RESULT_QR_DECODE_FAILED;
    }

    if (data.payload_len <= 0 || (size_t)data.payload_len > GPTNIX_QR_PAYLOAD_MAX_BYTES) {
        mbedtls_platform_zeroize(&data, sizeof(data));
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
        return GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
    }

    char qr_text[GPTNIX_QR_PAYLOAD_MAX_BYTES + 1];
    memcpy(qr_text, data.payload, (size_t)data.payload_len);
    qr_text[data.payload_len] = '\0';
    mbedtls_platform_zeroize(&data, sizeof(data));

    gptnix_qr_pair_result_t parse_result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
    gptnix_qr_pair_payload_t local_payload;
    memset(&local_payload, 0, sizeof(local_payload));

    cJSON *root = cJSON_Parse(qr_text);
    mbedtls_platform_zeroize(qr_text, sizeof(qr_text));

    if (root != NULL) {
        do {
            if (!cJSON_IsObject(root)) {
                break;
            }

            int key_count = 0;
            bool keys_valid = true;
            cJSON *child = NULL;
            cJSON_ArrayForEach(child, root) {
                key_count++;
                if (child->string == NULL
                    || (strcmp(child->string, "schemaVersion") != 0
                        && strcmp(child->string, "pairingId") != 0
                        && strcmp(child->string, "pairingValue") != 0)) {
                    keys_valid = false;
                }
            }
            if (!keys_valid || key_count != 3) {
                break;
            }

            cJSON *schema_item = cJSON_GetObjectItemCaseSensitive(root, "schemaVersion");
            cJSON *id_item = cJSON_GetObjectItemCaseSensitive(root, "pairingId");
            cJSON *value_item = cJSON_GetObjectItemCaseSensitive(root, "pairingValue");

            if (!cJSON_IsNumber(schema_item) || !cJSON_IsString(id_item) || !cJSON_IsString(value_item)) {
                break;
            }

            /* Require the mathematically exact integer 1 -- comparing the
             * full double avoids the truncation a valueint read would cause
             * for a non-integer input such as 1.5. */
            if (schema_item->valuedouble != 1.0) {
                break;
            }

            const char *id_str = id_item->valuestring;
            const char *value_str = value_item->valuestring;
            if (id_str == NULL || value_str == NULL) {
                break;
            }

            size_t id_len = strlen(id_str);
            size_t value_len = strlen(value_str);
            if (id_len == 0 || id_len > 128) {
                break;
            }
            if (value_len == 0 || value_len > 256) {
                break;
            }

            local_payload.schema_version = 1;
            memcpy(local_payload.pairing_id, id_str, id_len);
            local_payload.pairing_id[id_len] = '\0';
            memcpy(local_payload.pairing_value, value_str, value_len);
            local_payload.pairing_value[value_len] = '\0';

            parse_result = GPTNIX_QR_PAIR_RESULT_OK;
        } while (0);

        /* cJSON_Parse duplicates string values into its own heap-owned
         * nodes; cJSON_Delete() frees that memory but does not zero it
         * first. Explicitly zeroize any secret-bearing string content
         * still attached to the tree before releasing it, on every exit
         * path from the block above (success or any rejection). */
        cJSON *pid_for_wipe = cJSON_GetObjectItemCaseSensitive(root, "pairingId");
        if (cJSON_IsString(pid_for_wipe) && pid_for_wipe->valuestring != NULL) {
            mbedtls_platform_zeroize(pid_for_wipe->valuestring, strlen(pid_for_wipe->valuestring));
        }
        cJSON *pval_for_wipe = cJSON_GetObjectItemCaseSensitive(root, "pairingValue");
        if (cJSON_IsString(pval_for_wipe) && pval_for_wipe->valuestring != NULL) {
            mbedtls_platform_zeroize(pval_for_wipe->valuestring, strlen(pval_for_wipe->valuestring));
        }

        cJSON_Delete(root);
    }

    if (parse_result != GPTNIX_QR_PAIR_RESULT_OK) {
        app_gptnix_qr_pair_payload_clear(&local_payload);
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
        return GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
    }

    /* Only after the ENTIRE payload validated do we commit to the caller's
     * output -- no partially-populated success state is ever observable. */
    *out_payload = local_payload;
    app_gptnix_qr_pair_payload_clear(&local_payload);

    return GPTNIX_QR_PAIR_RESULT_OK;
}

#else /* !CONFIG_GPTNIX_QR_PAIRING */

esp_err_t app_gptnix_qr_pair_init(void)
{
    return ESP_OK;
}

void app_gptnix_qr_pair_deinit(void)
{
}

gptnix_qr_pair_result_t app_gptnix_qr_pair_decode_base64_jpeg(
    const char *image_b64,
    size_t image_b64_len,
    gptnix_qr_pair_payload_t *out_payload)
{
    (void)image_b64;
    (void)image_b64_len;
    ESP_LOGI(TAG, "[GPTNIX_QR_PAIR] decode: disabled");
    return GPTNIX_QR_PAIR_RESULT_DISABLED;
}

#endif /* CONFIG_GPTNIX_QR_PAIRING */
