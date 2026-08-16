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
 *
 * Secret-lifetime discipline: the pairing secret is a bearer secret
 * regardless of whether it is currently represented as JPEG bytes, RGB565
 * pixels, a grayscale QR frame, a decoded JSON string, or the final
 * pairing_value field. Every one of those representations is explicitly
 * zeroized once it is no longer needed for the current decode, on every
 * return path (success or failure), not only the plaintext-string forms.
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

#define GPTNIX_QR_IMAGE_WIDTH       (240)
#define GPTNIX_QR_IMAGE_HEIGHT      (240)
#define GPTNIX_QR_JPEG_MAX_BYTES    (49152) /* 48 KiB, matches the proven examples/qrcode_reader ceiling */
#define GPTNIX_QR_BASE64_MAX_BYTES  (65536)
#define GPTNIX_QR_PAYLOAD_MAX_BYTES (512)
#define GPTNIX_QR_RGB565_BYTES      (GPTNIX_QR_IMAGE_WIDTH * GPTNIX_QR_IMAGE_HEIGHT * 2) /* 115200 */
#define GPTNIX_QR_GRAY_BYTES        (GPTNIX_QR_IMAGE_WIDTH * GPTNIX_QR_IMAGE_HEIGHT)      /* 57600 */

static bool s_initialized = false;
static struct quirc *s_quirc = NULL;
static uint8_t *s_jpeg_buf = NULL;   /* GPTNIX_QR_JPEG_MAX_BYTES, decoded (base64->binary) JPEG bytes */
static uint8_t *s_rgb565_buf = NULL; /* GPTNIX_QR_RGB565_BYTES, 16-byte aligned JPEG decode output */

/* Zeroizes the module-owned JPEG and RGB565 scratch buffers in place
 * (never frees them). Both buffers can carry the QR-encoded pairing secret
 * as visually-encoded image data, not just as text, so they are wiped as
 * soon as their content is no longer needed for the current decode -- on
 * every return path, not only the eventual success path. */
static void s_wipe_image_scratch(void)
{
    if (s_jpeg_buf != NULL) {
        mbedtls_platform_zeroize(s_jpeg_buf, GPTNIX_QR_JPEG_MAX_BYTES);
    }
    if (s_rgb565_buf != NULL) {
        mbedtls_platform_zeroize(s_rgb565_buf, GPTNIX_QR_RGB565_BYTES);
    }
}

/* RGB565(BE)->grayscale lookup tables and conversion, values copied from
 * examples/qrcode_reader/main/isp.c::rgb565_to_gray(). That file belongs to
 * a separate, unwired example project (not reachable from factory_firmware's
 * build), so its proven algorithm is reproduced here as a PRIVATE helper
 * rather than introducing a second public ISP owner/module. This
 * specialization is fixed to this foundation's one proven format: a square
 * dim x dim buffer, ROTATION_UP, mirror=true -- the general
 * rotation/non-square/no-mirror cases of the original are intentionally not
 * reproduced, since this foundation never needs them. */
static const uint8_t s_rgb565_to_rgb888_table5[] = {
    0, 8, 16, 25, 33, 41, 49, 58, 66, 74, 82, 90, 99, 107, 115, 123,
    132, 140, 148, 156, 165, 173, 181, 189, 197, 206, 214, 222, 230, 239, 247, 255
};

static const uint8_t s_rgb565_to_rgb888_table6[] = {
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    130, 134, 138, 142, 146, 150, 154, 158, 162, 166, 170, 174, 178, 182, 186, 190,
    194, 198, 202, 206, 210, 215, 219, 223, 227, 231, 235, 239, 243, 247, 251, 255
};

static void s_rgb565_to_gray(uint8_t *pdst, const uint8_t *psrc, int dim)
{
    for (int i = 0; i < dim; i++) {
        for (int j = 0; j < dim; j++) {
            uint32_t index = (uint32_t)i * (uint32_t)dim + (uint32_t)j;

            uint8_t r = s_rgb565_to_rgb888_table5[(psrc[index * 2] & 0xF8) >> 3];
            uint8_t g = s_rgb565_to_rgb888_table6[((psrc[index * 2] & 0x07) << 3) | ((psrc[index * 2 + 1] & 0xE0) >> 5)];
            uint8_t b = s_rgb565_to_rgb888_table5[psrc[index * 2 + 1] & 0x1F];

            /* mirror=true; rotation=ROTATION_UP applies no transform of its own. */
            uint32_t out_index = (uint32_t)(dim - 1 - (int)(index / (uint32_t)dim)) * (uint32_t)dim + (index % (uint32_t)dim);

            pdst[out_index] = (uint8_t)(((uint32_t)r * 299 + (uint32_t)g * 587 + (uint32_t)b * 114) / 1000);
        }
    }
}

/* Unwinds exactly the resources already acquired at the point of a partial
 * init failure, or releases everything on a full deinit; never touches a
 * resource that was never acquired. Zeroizes image scratch content before
 * freeing it -- even though a completed decode() call already wipes it via
 * its own cleanup path, this is a defensive guarantee independent of that. */
static void s_unwind_partial_init(bool have_rgb565_buf, bool have_jpeg_buf, bool have_quirc)
{
    if (have_rgb565_buf && s_rgb565_buf != NULL) {
        mbedtls_platform_zeroize(s_rgb565_buf, GPTNIX_QR_RGB565_BYTES);
        free(s_rgb565_buf);
        s_rgb565_buf = NULL;
    }
    if (have_jpeg_buf && s_jpeg_buf != NULL) {
        mbedtls_platform_zeroize(s_jpeg_buf, GPTNIX_QR_JPEG_MAX_BYTES);
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

    /* From this point on, s_jpeg_buf and/or s_rgb565_buf may end up holding
     * QR-image-derived bytes before this function returns. Every exit below
     * sets `result` and `goto cleanup` instead of returning directly, so the
     * single shared cleanup path can unconditionally wipe both scratch
     * buffers (and correctly pair any quirc_begin()/close any jpeg_dec
     * handle) regardless of which path was taken -- this is deliberately
     * structured so no individual return site can be missed. */
    gptnix_qr_pair_result_t result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
    jpeg_dec_handle_t jpeg_dec = NULL;
    bool quirc_began = false;
    uint8_t *qbuf = NULL;

    size_t jpeg_len = 0;
    int b64_ret = mbedtls_base64_decode(
        s_jpeg_buf, GPTNIX_QR_JPEG_MAX_BYTES, &jpeg_len,
        (const unsigned char *)image_b64, image_b64_len);
    if (b64_ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        result = GPTNIX_QR_PAIR_RESULT_IMAGE_TOO_LARGE;
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_too_large");
        goto cleanup;
    }
    if (b64_ret != 0 || jpeg_len == 0) {
        result = GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
        goto cleanup;
    }

    {
        jpeg_dec_config_t jpeg_config = {
            .output_type = JPEG_RAW_TYPE_RGB565_BE,
            .rotate = JPEG_ROTATE_0D,
        };
        jpeg_dec = jpeg_dec_open(&jpeg_config);
    }
    if (jpeg_dec == NULL) {
        result = GPTNIX_QR_PAIR_RESULT_NO_MEMORY;
        ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: no_memory");
        goto cleanup;
    }

    {
        jpeg_dec_io_t jpeg_io;
        memset(&jpeg_io, 0, sizeof(jpeg_io));
        jpeg_dec_header_info_t jpeg_info;
        memset(&jpeg_info, 0, sizeof(jpeg_info));

        jpeg_io.inbuf = s_jpeg_buf;
        jpeg_io.inbuf_len = (int)jpeg_len;

        jpeg_error_t jret = jpeg_dec_parse_header(jpeg_dec, &jpeg_io, &jpeg_info);
        if (jret != JPEG_ERR_OK) {
            result = GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
            goto cleanup;
        }

        /* The fixed-size s_rgb565_buf is sized for exactly 240x240. Reject
         * any other JPEG dimensions BEFORE calling jpeg_dec_process, which
         * would otherwise write width*height*2 bytes into that fixed
         * buffer. */
        if (jpeg_info.width != GPTNIX_QR_IMAGE_WIDTH || jpeg_info.height != GPTNIX_QR_IMAGE_HEIGHT) {
            result = GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: unsupported_dimensions");
            goto cleanup;
        }

        jpeg_io.outbuf = s_rgb565_buf;
        int inbuf_consumed = jpeg_io.inbuf_len - jpeg_io.inbuf_remain;
        jpeg_io.inbuf = s_jpeg_buf + inbuf_consumed;
        jpeg_io.inbuf_len = jpeg_io.inbuf_remain;

        jret = jpeg_dec_process(jpeg_dec, &jpeg_io);
        if (jret != JPEG_ERR_OK) {
            result = GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: image_decode_failed");
            goto cleanup;
        }
    }

    {
        int qw = 0, qh = 0;
        qbuf = quirc_begin(s_quirc, &qw, &qh);
        if (qbuf != NULL) {
            quirc_began = true;
        }
        if (qbuf == NULL || qw != GPTNIX_QR_IMAGE_WIDTH || qh != GPTNIX_QR_IMAGE_HEIGHT) {
            result = GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: unsupported_dimensions");
            goto cleanup;
        }
    }

    /* Same orientation behavior as the proven examples/qrcode_reader path. */
    s_rgb565_to_gray(qbuf, s_rgb565_buf, GPTNIX_QR_IMAGE_WIDTH);

    /* s_jpeg_buf and s_rgb565_buf are now fully consumed for this decode --
     * wipe them at the earliest safe point, before anything further that
     * could itself fail and return. (cleanup below wipes them again
     * unconditionally as a defensive guarantee; a second wipe of already-
     * zeroed memory is harmless.) */
    s_wipe_image_scratch();

    /* quirc_end must run before quirc_count()/quirc_extract() -- it is what
     * finalizes quirc's internal per-frame QR search over the grayscale
     * buffer quirc_begin() returned. */
    quirc_end(s_quirc);
    quirc_began = false; /* already ended on this path; cleanup must not end it again */

    {
        int count = quirc_count(s_quirc);
        if (count == 0) {
            /* qbuf's content had its last required use inside quirc_end()
             * above; wipe the grayscale QR frame now. */
            mbedtls_platform_zeroize(qbuf, GPTNIX_QR_GRAY_BYTES);
            result = GPTNIX_QR_PAIR_RESULT_NO_CODE;
            ESP_LOGI(TAG, "[GPTNIX_QR_PAIR] decode: no_code");
            goto cleanup;
        }
        if (count > 1) {
            mbedtls_platform_zeroize(qbuf, GPTNIX_QR_GRAY_BYTES);
            result = GPTNIX_QR_PAIR_RESULT_AMBIGUOUS;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: ambiguous");
            goto cleanup;
        }
    }

    {
        struct quirc_code code;
        struct quirc_data data;
        quirc_extract(s_quirc, 0, &code);
        quirc_decode_error_t qerr = quirc_decode(&code, &data);
        mbedtls_platform_zeroize(&code, sizeof(code));

        /* qbuf's content had its last required use inside quirc_extract()/
         * quirc_decode() above; wipe the grayscale QR frame now, before any
         * further validation that could itself fail and return. */
        mbedtls_platform_zeroize(qbuf, GPTNIX_QR_GRAY_BYTES);

        if (qerr != QUIRC_SUCCESS) {
            mbedtls_platform_zeroize(&data, sizeof(data));
            result = GPTNIX_QR_PAIR_RESULT_QR_DECODE_FAILED;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
            goto cleanup;
        }

        if (data.payload_len <= 0 || (size_t)data.payload_len > GPTNIX_QR_PAYLOAD_MAX_BYTES) {
            mbedtls_platform_zeroize(&data, sizeof(data));
            result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
            goto cleanup;
        }

        /* Reject an embedded NUL before treating data.payload as a C
         * string -- otherwise a NUL earlier than data.payload_len would
         * hide bytes after it from every subsequent length-based check. */
        if (memchr(data.payload, '\0', (size_t)data.payload_len) != NULL) {
            mbedtls_platform_zeroize(&data, sizeof(data));
            result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
            goto cleanup;
        }

        char qr_text[GPTNIX_QR_PAYLOAD_MAX_BYTES + 1];
        size_t qr_text_len = (size_t)data.payload_len;
        memcpy(qr_text, data.payload, qr_text_len);
        qr_text[qr_text_len] = '\0';
        mbedtls_platform_zeroize(&data, sizeof(data));

        gptnix_qr_pair_result_t parse_result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
        gptnix_qr_pair_payload_t local_payload;
        memset(&local_payload, 0, sizeof(local_payload));

        /* cJSON_ParseWithLengthOpts with require_null_terminated=1 and a
         * buffer_length bound to exactly qr_text_len+1 enforces that the
         * ENTIRE declared payload is one complete JSON document: it parses
         * one value, skips only JSON-grammar whitespace after it, and then
         * requires the very next byte (within that exact bound) to be the
         * NUL terminator we wrote. A second concatenated JSON document or
         * any other non-whitespace trailing byte occupies that position
         * instead of NUL, so parsing fails closed. */
        const char *parse_end = NULL;
        cJSON *root = cJSON_ParseWithLengthOpts(qr_text, qr_text_len + 1, &parse_end, 1);
        bool full_consumption_confirmed = (root != NULL) && (parse_end == qr_text + qr_text_len);
        mbedtls_platform_zeroize(qr_text, sizeof(qr_text));

        if (root != NULL) {
            if (full_consumption_confirmed) {
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

                    /* Require the mathematically exact integer 1 -- comparing
                     * the full double avoids the truncation a valueint read
                     * would cause for a non-integer input such as 1.5. */
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
            }

            /* cJSON_Parse*() duplicates string values into its own
             * heap-owned nodes; cJSON_Delete() frees that memory but does
             * not zero it first. Explicitly zeroize any secret-bearing
             * string content still attached to the tree before releasing
             * it, on every exit path from the block above (success or any
             * rejection, including the full_consumption_confirmed=false
             * case). */
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
            result = GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD;
            ESP_LOGW(TAG, "[GPTNIX_QR_PAIR] decode: invalid_payload");
            goto cleanup;
        }

        /* Only after the ENTIRE payload validated do we commit to the
         * caller's output -- no partially-populated success state is ever
         * observable. */
        *out_payload = local_payload;
        app_gptnix_qr_pair_payload_clear(&local_payload);
        result = GPTNIX_QR_PAIR_RESULT_OK;
    }

cleanup:
    if (quirc_began) {
        /* Reached only when quirc_begin() succeeded but this function did
         * not already call quirc_end() earlier on the current path
         * (the unsupported-dimensions-after-begin case). Keep the pairing
         * and wipe the frame the same way the main flow does. */
        quirc_end(s_quirc);
        if (qbuf != NULL) {
            mbedtls_platform_zeroize(qbuf, GPTNIX_QR_GRAY_BYTES);
        }
    }
    if (jpeg_dec != NULL) {
        jpeg_dec_close(jpeg_dec);
    }
    /* Unconditional final wipe: covers every path that reached `goto
     * cleanup` before the earlier in-flow wipe point (e.g. any JPEG/base64
     * failure), and is a harmless no-op re-wipe on paths that already wiped
     * these buffers. */
    s_wipe_image_scratch();
    return result;
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
    if (out_payload != NULL) {
        app_gptnix_qr_pair_payload_clear(out_payload);
    }
    ESP_LOGI(TAG, "[GPTNIX_QR_PAIR] decode: disabled");
    return GPTNIX_QR_PAIR_RESULT_DISABLED;
}

#endif /* CONFIG_GPTNIX_QR_PAIRING */
