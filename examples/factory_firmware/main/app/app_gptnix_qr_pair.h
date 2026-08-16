/**
 * GPTNiX Watcher QR pairing decoder/parser foundation.
 *
 * Canonical, compile-time gated (CONFIG_GPTNIX_QR_PAIRING) owner of QR
 * pairing-secret decode/parse for the GPTNiX pairing transport contract
 * (see docs/GPTNIX_QR_PAIRING_CONTRACT_V1.md). This module owns only QR
 * decode/parser resources. It does not own the SSCMA client, camera
 * lifecycle, UI, HTTP transport, Firebase, or persistent storage.
 */
#ifndef APP_GPTNIX_QR_PAIR_H
#define APP_GPTNIX_QR_PAIR_H

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GPTNIX_QR_PAIR_RESULT_OK = 0,
    GPTNIX_QR_PAIR_RESULT_DISABLED,
    GPTNIX_QR_PAIR_RESULT_NOT_INITIALIZED,
    GPTNIX_QR_PAIR_RESULT_INVALID_ARGUMENT,
    GPTNIX_QR_PAIR_RESULT_IMAGE_TOO_LARGE,
    GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED,
    GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS,
    GPTNIX_QR_PAIR_RESULT_NO_CODE,
    GPTNIX_QR_PAIR_RESULT_AMBIGUOUS,
    GPTNIX_QR_PAIR_RESULT_QR_DECODE_FAILED,
    GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD,
    GPTNIX_QR_PAIR_RESULT_NO_MEMORY,
} gptnix_qr_pair_result_t;

typedef struct {
    uint32_t schema_version;
    char pairing_id[129];
    char pairing_value[257];
} gptnix_qr_pair_payload_t;

/**
 * Initialize the module. When CONFIG_GPTNIX_QR_PAIRING is disabled this is
 * side-effect-free and always returns ESP_OK. When enabled, allocates the
 * module-owned quirc context and bounded decode buffers exactly once.
 */
esp_err_t app_gptnix_qr_pair_init(void);

/**
 * Release every module-owned resource exactly once. Idempotent: safe to call
 * when not initialized or after a prior deinit.
 */
void app_gptnix_qr_pair_deinit(void);

/**
 * Decode a base64-encoded JPEG image (as produced by
 * sscma_utils_fetch_image_from_reply) into a validated pairing payload.
 *
 * `image_b64` is BORROWED — this function never frees or mutates it. The
 * caller retains ownership and is responsible for freeing it after this
 * call returns.
 */
gptnix_qr_pair_result_t app_gptnix_qr_pair_decode_base64_jpeg(
    const char *image_b64,
    size_t image_b64_len,
    gptnix_qr_pair_payload_t *out_payload
);

/**
 * Explicitly zeroize a payload structure through a compiler-resistant
 * zeroization implementation (mbedtls_platform_zeroize). Safe to call on an
 * already-cleared or stack-allocated-but-unused structure.
 */
void app_gptnix_qr_pair_payload_clear(gptnix_qr_pair_payload_t *payload);

#ifdef __cplusplus
}
#endif

#endif /* APP_GPTNIX_QR_PAIR_H */
