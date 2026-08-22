/**
 * GPTNiX Watcher realtime-voice WSS transport/session foundation.
 *
 * See app_gptnix_watcher_voice.h for the public contract and
 * docs/GPTNIX_WATCHER_VOICE_TRANSPORT_CONTRACT_V1.md for the full transport
 * contract. This module owns only the Gemini Live WebSocket transport/
 * session lifecycle: consuming a backend-provisioned session DTO, opening
 * one esp_websocket_client connection, sending the backend's `client.setup`
 * object verbatim, and recognizing `{"setupComplete":{}}` before READY.
 *
 * M2 scope: transport/session foundation ONLY. This module never touches
 * the microphone/speaker owners, never builds an audio streaming message of
 * any kind, never calls any cloud identity/pairing/session-provisioning
 * HTTP endpoint, and is never called from any runtime call site in this
 * milestone.
 *
 * Secret-lifetime discipline: the ephemeral bearer token is a secret
 * regardless of representation (parsed JSON string, module-owned RAM copy,
 * or a temporary "Token <token>" header value). Every representation this
 * module itself owns is zeroized once no longer needed. The one documented
 * exception is the third-party esp_websocket_client component's own
 * internal copy of the appended Authorization header value -- that memory
 * is owned and freed (not zeroized) by the library itself when the client
 * is destroyed; this module cannot patch third-party internals in M2. This
 * is a residual RAM-lifetime limitation of the canary transport library,
 * documented here and in the contract doc, not a defect this module hides.
 */
#include "app_gptnix_watcher_voice.h"
#include "sdkconfig.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "mbedtls/platform_util.h"

#if CONFIG_GPTNIX_WATCHER_VOICE

#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_websocket_client.h"
#include "freertos/FreeRTOS.h"
#include "mbedtls/base64.h"

static const char *TAG = "V2_WATCHER_VOICE";

#define GPTNIX_WATCHER_VOICE_SESSION_DTO_MAX_BYTES   (65536)
#define GPTNIX_WATCHER_VOICE_ENDPOINT_MAX_BYTES      (512)
#define GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES         (2048)
#define GPTNIX_WATCHER_VOICE_SETUP_JSON_MAX_BYTES    (32768)
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with real speech
// revealed Gemini's actual serverContent audio response messages are FAR larger than the original
// 8192-byte sizing (chosen when this buffer only ever needed to hold the ~26-byte setupComplete message)
// -- observed real fragments up to 33547 bytes in one message. Sized generously above the largest
// observed real message with headroom for longer utterances; PSRAM is used for other buffers in this
// module already and ESP32-S3 has 8MB available, so this is not a scarce resource.
#define GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES (65536)
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with real speech showed
// the WS text-send call failing (sent != msg_len) for a realistic-size mic audio chunk (16000 raw PCM
// bytes -> ~21.4KB once base64-encoded plus the JSON envelope). ESP-IDF's own internal
// auto-fragmentation for oversized sends has known reliability issues (multiple upstream GitHub issues
// report corrupted/failed large-payload sends) -- sized generously above the largest realistic outgoing
// message instead of relying on that path.
#define GPTNIX_WATCHER_VOICE_WS_BUFFER_BYTES         (32768)
#define GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS      (10000)
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): two separate live physical tests (multi-turn
// conversation) showed the ENTIRE session going silent -- not just outgoing sends failing, but Gemini's
// own incoming replies and even routine turn-signal acks stopping completely -- once the mic-audio-send
// task fell behind and started retrying a backlog of pieces. Hypothesized cause: app_gptnix_watcher_
// voice_send_audio() reusing the full 10s GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS per piece, combined
// with esp_websocket_client's send/receive paths sharing one lock by default, starving receive processing
// during a long blocked send. Tried 300ms as a dedicated, much shorter timeout for this ONE call site --
// a live physical test then showed a WORSE regression (complete silence, not even the routine idle acks,
// reproduced twice including with zero user speech yet). Likely cause: 300ms fails almost every send
// attempt outright, so the send task now retries in a tight loop, taking/releasing the shared lock far
// MORE frequently than the original 10s timeout ever did -- more frequent short contentions apparently
// starve the receive side worse than fewer long ones. Reverted to the original 10000ms pending a
// differently-shaped fix (e.g. backoff between retries, not just a shorter per-call timeout).
#define GPTNIX_WATCHER_VOICE_AUDIO_SEND_TIMEOUT_MS   (10000)

/* M3C runtime audio bridge (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md). Mic input matches Gemini's expected
 * realtimeInput rate exactly (16kHz/16-bit/mono, the BSP's fixed capture rate) -- no resampling needed.
 * Gemini's spoken response is always 24kHz/16-bit/mono; the audio player supports a per-stream sample
 * rate declared via a standard 44-byte WAV header on the FIRST chunk of a stream (see
 * app_audio_player.c's __is_wav()/__audio_player_set_fs()), so a synthesized WAV header is used instead
 * of a software resampler -- avoids touching the shared TX/RX I2S/codec clock config directly. */
#define GPTNIX_WATCHER_VOICE_AUDIO_OUT_SAMPLE_RATE   (24000)
#define GPTNIX_WATCHER_VOICE_AUDIO_BITS_PER_SAMPLE   (16)
#define GPTNIX_WATCHER_VOICE_AUDIO_CHANNELS          (1)
/* Bounds a single outgoing mic chunk (base64-inflated ~4/3, plus JSON envelope) and a single incoming
 * Gemini audio chunk (base64-decoded from the RX reassembly buffer) -- generous relative to realistic
 * per-message sizes (tens of ms of audio), never assumed to hold an entire utterance at once. */
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): must stay >= RX_REASSEMBLY_MAX_BYTES,
// since a single inlineData base64 string can occupy nearly the whole reassembled message.
#define GPTNIX_WATCHER_VOICE_AUDIO_CHUNK_MAX_BYTES   (65536)

/* Bound is intentionally generous but finite -- no exact model-id length is
 * specified by the backend contract; this only prevents an unbounded copy. */
#define GPTNIX_WATCHER_VOICE_MODEL_MAX_BYTES (256)

struct app_gptnix_watcher_voice {
    app_gptnix_watcher_voice_state_t state;
    app_gptnix_watcher_voice_result_t last_result;
    esp_websocket_client_handle_t ws_client;

    char endpoint[GPTNIX_WATCHER_VOICE_ENDPOINT_MAX_BYTES];
    size_t endpoint_len;
    char token[GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES];
    size_t token_len;
    char setup_json[GPTNIX_WATCHER_VOICE_SETUP_JSON_MAX_BYTES];
    size_t setup_json_len;

    uint8_t rx_buf[GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES];
    int rx_accumulated;
    int rx_payload_len;

};

/* M3C: registered by an external module (app_gptnix_watcher_voice_runtime.c) -- this module never calls
 * the audio player itself (a pre-existing, fitness-enforced separation-of-concerns boundary). Static,
 * not per-ctx: wiring is a one-time startup concern, not per-session state. */
static app_gptnix_watcher_voice_audio_cb_t s_audio_cb = NULL;
static void *s_audio_cb_user_data = NULL;

void app_gptnix_watcher_voice_set_audio_callback(app_gptnix_watcher_voice_audio_cb_t cb, void *user_data)
{
    s_audio_cb = cb;
    s_audio_cb_user_data = user_data;
}

static struct app_gptnix_watcher_voice *s_ctx = NULL;

static void s_ws_event_handler(void *handler_args,
                                esp_event_base_t base,
                                int32_t event_id,
                                void *event_data);

/* Zeroizes every session-material representation this module owns. Does not
 * free s_ctx itself -- callers decide lifetime (reused across sessions by
 * prepare_session, or released once by deinit). */
static void s_clear_session_material(struct app_gptnix_watcher_voice *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_platform_zeroize(ctx->endpoint, sizeof(ctx->endpoint));
    mbedtls_platform_zeroize(ctx->token, sizeof(ctx->token));
    mbedtls_platform_zeroize(ctx->setup_json, sizeof(ctx->setup_json));
    mbedtls_platform_zeroize(ctx->rx_buf, sizeof(ctx->rx_buf));
    ctx->endpoint_len = 0;
    ctx->token_len = 0;
    ctx->setup_json_len = 0;
    ctx->rx_accumulated = 0;
    ctx->rx_payload_len = 0;
}

/* Recursively zeroizes every non-NULL valuestring reachable from `item`
 * (siblings via ->next, children via ->child), without freeing or altering
 * cJSON tree structure. cJSON_Delete() already performs an equivalent
 * recursive traversal to free nodes; this walks the same shape first to
 * scrub secret-bearing string content before that memory is released.
 * Accepts NULL safely. Never logs, never allocates. */
static void s_zeroize_cjson_valuestrings(cJSON *item)
{
    while (item != NULL) {
        if (item->valuestring != NULL) {
            mbedtls_platform_zeroize(item->valuestring, strlen(item->valuestring) + 1);
        }
        if (item->child != NULL) {
            s_zeroize_cjson_valuestrings(item->child);
        }
        item = item->next;
    }
}

/* Zeroizes every secret-bearing string in the parsed tree before releasing
 * it -- cJSON_Delete() frees but does not zero string memory first. Use for
 * the parsed session DTO root, which may carry client.auth.token. */
static void s_sensitive_cjson_delete(cJSON **item)
{
    if (item == NULL || *item == NULL) {
        return;
    }
    s_zeroize_cjson_valuestrings(*item);
    cJSON_Delete(*item);
    *item = NULL;
}

/* Zeroizes a cJSON-allocated string (e.g. from cJSON_PrintUnformatted)
 * before releasing it via cJSON_free(). Use for the printed setup JSON,
 * which is the exact wire message firmware will send and therefore is not
 * itself a secret, but is treated with the same deterministic cleanup path
 * as the rest of this module's session material per its own contract. */
static void s_sensitive_cjson_free_string(char **value)
{
    if (value == NULL || *value == NULL) {
        return;
    }
    size_t len = strlen(*value);
    mbedtls_platform_zeroize(*value, len + 1);
    cJSON_free(*value);
    *value = NULL;
}

/* Terminal pre-running-client failure cleanup for connect(). Callable only
 * when ws_client is already NULL -- either because a client was never
 * created on this attempt, or because the caller already destroyed a
 * partially-set-up client and set ws_client to NULL immediately before
 * calling this. Never destroys a client itself; that responsibility stays
 * with the caller so every destroy call site remains visible in connect(). */
static app_gptnix_watcher_voice_result_t s_fail_before_running_client(
    struct app_gptnix_watcher_voice *ctx,
    app_gptnix_watcher_voice_result_t result)
{
    s_clear_session_material(ctx);
    ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
    ctx->last_result = result;
    return result;
}

esp_err_t app_gptnix_watcher_voice_init(void)
{
    if (s_ctx != NULL) {
        return ESP_OK;
    }
    s_ctx = (struct app_gptnix_watcher_voice *)heap_caps_calloc(
        1, sizeof(struct app_gptnix_watcher_voice), MALLOC_CAP_SPIRAM);
    if (s_ctx == NULL) {
        return ESP_ERR_NO_MEM;
    }
    s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_IDLE;
    s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_OK;
    s_ctx->ws_client = NULL;
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE] init: enabled");
    return ESP_OK;
}

esp_err_t app_gptnix_watcher_voice_deinit(void)
{
    if (s_ctx == NULL) {
        return ESP_OK;
    }
    if (s_ctx->ws_client != NULL) {
        /* Caller-side terminal cleanup only -- never invoked from the
         * websocket event task, so stop() here is safe per component docs. */
        esp_websocket_client_stop(s_ctx->ws_client);
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
    }
    s_clear_session_material(s_ctx);
    free(s_ctx);
    s_ctx = NULL;
    return ESP_OK;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_prepare_session(
    const char *session_json,
    size_t session_len)
{
    if (s_ctx == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    /* Single-client lifecycle: a session may only be prepared from IDLE with
     * no existing client handle. M2 has no reset/reuse API -- a caller must
     * disconnect()/deinit()/init() before preparing another session. This
     * check runs before any parsing/allocation and never mutates state. */
    if (s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_IDLE || s_ctx->ws_client != NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    if (session_json == NULL || session_len == 0) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    if (session_len > GPTNIX_WATCHER_VOICE_SESSION_DTO_MAX_BYTES) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    /* Reject an embedded NUL before treating the input as JSON text at all. */
    if (memchr(session_json, '\0', session_len) != NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_SESSION_DTO;
    }

    char *dto_copy = (char *)heap_caps_malloc(session_len + 1, MALLOC_CAP_SPIRAM);
    if (dto_copy == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
    }
    memcpy(dto_copy, session_json, session_len);
    dto_copy[session_len] = '\0';

    /* require_null_terminated=1 with buffer_length exactly session_len+1
     * enforces full consumption of the intended input: after the one JSON
     * value (and any trailing JSON whitespace), the next byte within that
     * exact bound must be the NUL we wrote -- trailing garbage or a second
     * concatenated document occupies that position instead and fails
     * closed. */
    const char *parse_end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(dto_copy, session_len + 1, &parse_end, 1);
    bool full_consumption = (root != NULL) && (parse_end == dto_copy + session_len);
    /* dto_copy may carry the full raw DTO, including the ephemeral token
     * text, verbatim -- zeroize before free, not after. */
    mbedtls_platform_zeroize(dto_copy, session_len + 1);
    free(dto_copy);
    dto_copy = NULL;

    app_gptnix_watcher_voice_result_t result = GPTNIX_WATCHER_VOICE_RESULT_INVALID_SESSION_DTO;
    char local_endpoint[GPTNIX_WATCHER_VOICE_ENDPOINT_MAX_BYTES];
    char local_token[GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES];
    size_t local_endpoint_len = 0;
    size_t local_token_len = 0;
    char *local_setup_json = NULL;
    size_t local_setup_json_len = 0;
    memset(local_endpoint, 0, sizeof(local_endpoint));
    memset(local_token, 0, sizeof(local_token));

    if (root != NULL) {
        if (full_consumption && cJSON_IsObject(root)) {
            do {
                cJSON *schema_item = cJSON_GetObjectItemCaseSensitive(root, "schemaVersion");
                if (!cJSON_IsNumber(schema_item) || schema_item->valuedouble != 1.0) break;

                cJSON *provider_item = cJSON_GetObjectItemCaseSensitive(root, "provider");
                if (!cJSON_IsString(provider_item) || provider_item->valuestring == NULL
                    || strcmp(provider_item->valuestring, "gemini") != 0) break;

                cJSON *mode_item = cJSON_GetObjectItemCaseSensitive(root, "mode");
                if (!cJSON_IsString(mode_item) || mode_item->valuestring == NULL
                    || strcmp(mode_item->valuestring, "realtime_audio") != 0) break;

                cJSON *model_item = cJSON_GetObjectItemCaseSensitive(root, "model");
                if (!cJSON_IsString(model_item) || model_item->valuestring == NULL) break;
                size_t model_len = strlen(model_item->valuestring);
                if (model_len == 0 || model_len > GPTNIX_WATCHER_VOICE_MODEL_MAX_BYTES) break;

                cJSON *client_item = cJSON_GetObjectItemCaseSensitive(root, "client");
                if (!cJSON_IsObject(client_item)) break;

                cJSON *transport_item = cJSON_GetObjectItemCaseSensitive(client_item, "transport");
                if (!cJSON_IsString(transport_item) || transport_item->valuestring == NULL
                    || strcmp(transport_item->valuestring, "websocket") != 0) break;

                cJSON *endpoint_item = cJSON_GetObjectItemCaseSensitive(client_item, "endpoint");
                if (!cJSON_IsString(endpoint_item) || endpoint_item->valuestring == NULL) break;
                const char *endpoint_str = endpoint_item->valuestring;
                size_t endpoint_len = strlen(endpoint_str);
                if (endpoint_len == 0 || endpoint_len > 511) break;
                if (strncmp(endpoint_str, "wss://", 6) != 0) break;
                if (memchr(endpoint_str, '\r', endpoint_len) != NULL) break;
                if (memchr(endpoint_str, '\n', endpoint_len) != NULL) break;
                if (strstr(endpoint_str, "access_token=") != NULL) break;
                if (memchr(endpoint_str, '#', endpoint_len) != NULL) break;
                {
                    const char *authority = endpoint_str + 6; /* past "wss://" */
                    const char *first_slash = strchr(authority, '/');
                    size_t authority_len = (first_slash != NULL)
                        ? (size_t)(first_slash - authority)
                        : strlen(authority);
                    if (memchr(authority, '@', authority_len) != NULL) break;
                }

                cJSON *auth_item = cJSON_GetObjectItemCaseSensitive(client_item, "auth");
                if (!cJSON_IsObject(auth_item)) break;
                cJSON *auth_type = cJSON_GetObjectItemCaseSensitive(auth_item, "type");
                cJSON *auth_placement = cJSON_GetObjectItemCaseSensitive(auth_item, "placement");
                cJSON *auth_header = cJSON_GetObjectItemCaseSensitive(auth_item, "header");
                cJSON *auth_scheme = cJSON_GetObjectItemCaseSensitive(auth_item, "scheme");
                cJSON *auth_token = cJSON_GetObjectItemCaseSensitive(auth_item, "token");
                if (!cJSON_IsString(auth_type) || auth_type->valuestring == NULL
                    || strcmp(auth_type->valuestring, "ephemeral_token") != 0) break;
                if (!cJSON_IsString(auth_placement) || auth_placement->valuestring == NULL
                    || strcmp(auth_placement->valuestring, "header") != 0) break;
                if (!cJSON_IsString(auth_header) || auth_header->valuestring == NULL
                    || strcmp(auth_header->valuestring, "Authorization") != 0) break;
                if (!cJSON_IsString(auth_scheme) || auth_scheme->valuestring == NULL
                    || strcmp(auth_scheme->valuestring, "Token") != 0) break;
                if (!cJSON_IsString(auth_token) || auth_token->valuestring == NULL) break;
                size_t token_len = strlen(auth_token->valuestring);
                if (token_len == 0 || token_len > 2047) break;
                /* Legacy query-placement "parameter" field must be absent. */
                if (cJSON_HasObjectItem(auth_item, "parameter")) break;

                cJSON *setup_item = cJSON_GetObjectItemCaseSensitive(client_item, "setup");
                if (!cJSON_IsObject(setup_item)) break;

                /* Serialize client.setup ITSELF -- this is exactly the wire
                 * message firmware must send, not client.setup.setup and not
                 * a further {"setup": ...} wrapper around it. */
                char *printed = cJSON_PrintUnformatted(setup_item);
                if (printed == NULL) break;
                size_t printed_len = strlen(printed);
                if (printed_len == 0 || printed_len > 32767) { s_sensitive_cjson_free_string(&printed); break; }

                /* Require exactly one top-level key, named "setup". */
                {
                    int key_count = 0;
                    bool has_setup_key = false;
                    cJSON *child = NULL;
                    cJSON_ArrayForEach(child, setup_item) {
                        key_count++;
                        if (child->string != NULL && strcmp(child->string, "setup") == 0) {
                            has_setup_key = true;
                        }
                    }
                    if (key_count != 1 || !has_setup_key) { s_sensitive_cjson_free_string(&printed); break; }
                }

                cJSON *inner_setup = cJSON_GetObjectItemCaseSensitive(setup_item, "setup");
                if (!cJSON_IsObject(inner_setup)) { s_sensitive_cjson_free_string(&printed); break; }

                /* Consistency validation only: setup.setup.model must equal
                 * "models/" + top-level model. Firmware never generates or
                 * chooses this value -- it only proves the backend's own DTO
                 * is internally consistent before trusting it. */
                cJSON *inner_model = cJSON_GetObjectItemCaseSensitive(inner_setup, "model");
                if (!cJSON_IsString(inner_model) || inner_model->valuestring == NULL) { s_sensitive_cjson_free_string(&printed); break; }
                {
                    size_t expected_len = strlen("models/") + model_len;
                    if (strlen(inner_model->valuestring) != expected_len
                        || strncmp(inner_model->valuestring, "models/", 7) != 0
                        || strcmp(inner_model->valuestring + 7, model_item->valuestring) != 0) {
                        s_sensitive_cjson_free_string(&printed);
                        break;
                    }
                }

                cJSON *gen_config = cJSON_GetObjectItemCaseSensitive(inner_setup, "generationConfig");
                if (!cJSON_IsObject(gen_config)) { s_sensitive_cjson_free_string(&printed); break; }
                cJSON *modalities = cJSON_GetObjectItemCaseSensitive(gen_config, "responseModalities");
                if (!cJSON_IsArray(modalities)) { s_sensitive_cjson_free_string(&printed); break; }
                {
                    int audio_count = 0;
                    cJSON *m = NULL;
                    cJSON_ArrayForEach(m, modalities) {
                        if (cJSON_IsString(m) && m->valuestring != NULL
                            && strcmp(m->valuestring, "AUDIO") == 0) {
                            audio_count++;
                        }
                    }
                    if (audio_count != 1) { s_sensitive_cjson_free_string(&printed); break; }
                }

                if (endpoint_len >= sizeof(local_endpoint)
                    || token_len >= sizeof(local_token)
                    || printed_len >= GPTNIX_WATCHER_VOICE_SETUP_JSON_MAX_BYTES) {
                    /* Defensive: unreachable given the bound checks above. */
                    s_sensitive_cjson_free_string(&printed);
                    break;
                }

                memcpy(local_endpoint, endpoint_str, endpoint_len);
                local_endpoint[endpoint_len] = '\0';
                local_endpoint_len = endpoint_len;

                memcpy(local_token, auth_token->valuestring, token_len);
                local_token[token_len] = '\0';
                local_token_len = token_len;

                local_setup_json = (char *)heap_caps_malloc(printed_len + 1, MALLOC_CAP_SPIRAM);
                if (local_setup_json == NULL) {
                    s_sensitive_cjson_free_string(&printed);
                    result = GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
                    break;
                }
                memcpy(local_setup_json, printed, printed_len + 1);
                local_setup_json_len = printed_len;
                s_sensitive_cjson_free_string(&printed);

                result = GPTNIX_WATCHER_VOICE_RESULT_OK;
            } while (0);
        }
        s_sensitive_cjson_delete(&root);
    }

    if (result == GPTNIX_WATCHER_VOICE_RESULT_OK) {
        s_clear_session_material(s_ctx);
        memcpy(s_ctx->endpoint, local_endpoint, local_endpoint_len + 1);
        s_ctx->endpoint_len = local_endpoint_len;
        memcpy(s_ctx->token, local_token, local_token_len + 1);
        s_ctx->token_len = local_token_len;
        memcpy(s_ctx->setup_json, local_setup_json, local_setup_json_len + 1);
        s_ctx->setup_json_len = local_setup_json_len;
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_SESSION_READY;
        ESP_LOGI(TAG, "[V2_WATCHER_VOICE] session_ready: setup_bytes=%d", (int)local_setup_json_len);
    }

    mbedtls_platform_zeroize(local_endpoint, sizeof(local_endpoint));
    mbedtls_platform_zeroize(local_token, sizeof(local_token));
    if (local_setup_json != NULL) {
        mbedtls_platform_zeroize(local_setup_json, local_setup_json_len);
        free(local_setup_json);
        local_setup_json = NULL;
    }

    return result;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_connect(void)
{
    if (s_ctx == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    /* Single-client lifecycle: connect() is only accepted from SESSION_READY
     * with no existing client handle -- prevents a second live client from
     * ever overwriting s_ctx->ws_client. No mutation on rejection. */
    if (s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_SESSION_READY
        || s_ctx->ws_client != NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }

    char auth_value[GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES + 8]; /* "Token " + token + NUL */
    int written = snprintf(auth_value, sizeof(auth_value), "Token %s", s_ctx->token);
    if (written < 0 || (size_t)written >= sizeof(auth_value)) {
        mbedtls_platform_zeroize(auth_value, sizeof(auth_value));
        return s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED);
    }

    esp_websocket_client_config_t config;
    memset(&config, 0, sizeof(config));
    config.uri = s_ctx->endpoint;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.disable_auto_reconnect = true;
    config.network_timeout_ms = GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS;
    config.buffer_size = GPTNIX_WATCHER_VOICE_WS_BUFFER_BYTES;
    config.user_context = s_ctx;

    s_ctx->ws_client = esp_websocket_client_init(&config);
    if (s_ctx->ws_client == NULL) {
        mbedtls_platform_zeroize(auth_value, sizeof(auth_value));
        return s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED);
    }

    esp_err_t header_err = esp_websocket_client_append_header(s_ctx->ws_client, "Authorization", auth_value);
    /* The library copies this value into its own heap-owned header state
     * during append -- safe to zeroize our temporary copy immediately.
     * GPTNiX itself never needs the module-owned token again after this
     * point (no auth retry, no reconnect, no second setup/header
     * construction) -- scrub it now at point of last use rather than
     * waiting for terminal/disconnect cleanup. */
    mbedtls_platform_zeroize(auth_value, sizeof(auth_value));
    mbedtls_platform_zeroize(s_ctx->token, sizeof(s_ctx->token));
    s_ctx->token_len = 0;
    if (header_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        return s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED);
    }

    esp_err_t reg_err = esp_websocket_register_events(
        s_ctx->ws_client, WEBSOCKET_EVENT_ANY, s_ws_event_handler, s_ctx);
    if (reg_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        return s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED);
    }

    s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_CONNECTING;

    esp_err_t start_err = esp_websocket_client_start(s_ctx->ws_client);
    if (start_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        return s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_START_FAILED);
    }

    return GPTNIX_WATCHER_VOICE_RESULT_OK;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_disconnect(void)
{
    if (s_ctx == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    if (s_ctx->ws_client != NULL) {
        /* Caller context only -- never called from the event handler. */
        esp_websocket_client_stop(s_ctx->ws_client);
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
    }
    s_clear_session_material(s_ctx);
    s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_CLOSED;
    return GPTNIX_WATCHER_VOICE_RESULT_OK;
}

app_gptnix_watcher_voice_state_t app_gptnix_watcher_voice_get_state(void)
{
    if (s_ctx == NULL) {
        return GPTNIX_WATCHER_VOICE_STATE_UNINITIALIZED;
    }
    return s_ctx->state;
}

/* M3C runtime audio bridge (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md). Caller context only (never called
 * from the WS event handler). Never logs pcm_data content or the base64/JSON it produces -- only a
 * fixed-shape structural log line with byte counts. */
app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_send_audio(const uint8_t *pcm_data, size_t pcm_len)
{
    if (s_ctx == NULL || pcm_data == NULL || pcm_len == 0
        || pcm_len > GPTNIX_WATCHER_VOICE_AUDIO_CHUNK_MAX_BYTES) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }
    if (s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_READY) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }

    size_t b64_cap = 0;
    mbedtls_base64_encode(NULL, 0, &b64_cap, pcm_data, pcm_len); /* returns required length in b64_cap */
    char *b64_buf = (char *)heap_caps_malloc(b64_cap + 1, MALLOC_CAP_SPIRAM);
    if (b64_buf == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
    }
    size_t b64_len = 0;
    int b64_err = mbedtls_base64_encode((uint8_t *)b64_buf, b64_cap, &b64_len, pcm_data, pcm_len);
    if (b64_err != 0) {
        free(b64_buf);
        return GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
    }
    b64_buf[b64_len] = '\0';

    cJSON *audio_req_root = cJSON_CreateObject();
    cJSON *realtime_input = cJSON_CreateObject();
    cJSON *audio = cJSON_CreateObject();
    if (audio_req_root == NULL || realtime_input == NULL || audio == NULL) {
        if (audio_req_root != NULL) cJSON_Delete(audio_req_root);
        else { if (realtime_input) cJSON_Delete(realtime_input); if (audio) cJSON_Delete(audio); }
        mbedtls_platform_zeroize(b64_buf, b64_len + 1);
        free(b64_buf);
        return GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
    }
    cJSON_AddItemToObject(audio_req_root, "realtimeInput", realtime_input);
    cJSON_AddItemToObject(realtime_input, "audio", audio);
    cJSON_AddStringToObject(audio, "data", b64_buf);
    cJSON_AddStringToObject(audio, "mimeType", "audio/pcm;rate=16000");

    mbedtls_platform_zeroize(b64_buf, b64_len + 1);
    free(b64_buf);

    char *msg = cJSON_PrintUnformatted(audio_req_root);
    cJSON_Delete(audio_req_root);
    if (msg == NULL) {
        return GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY;
    }
    size_t msg_len = strlen(msg);

    // M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the user reported latency far
    // beyond what tuning buffer sizes/timeouts alone could explain. Timing this ONE call directly settles
    // whether the bottleneck is achievable network/TLS throughput on this hardware (a real ceiling no
    // amount of app-level tuning can fix) versus something else. Never logs message content.
    int64_t send_start_us = esp_timer_get_time();
    int sent = esp_websocket_client_send_text(
        s_ctx->ws_client, msg, (int)msg_len, pdMS_TO_TICKS(GPTNIX_WATCHER_VOICE_AUDIO_SEND_TIMEOUT_MS));
    int64_t send_elapsed_ms = (esp_timer_get_time() - send_start_us) / 1000;
    cJSON_free(msg);

    ESP_LOGI(TAG, "[V2_WATCHER_VOICE] audio_send: elapsed_ms=%lld msg_len=%d pcm_len=%d",
        (long long)send_elapsed_ms, (int)msg_len, (int)pcm_len);

    if (sent != (int)msg_len) {
        ESP_LOGW(TAG, "[V2_WATCHER_VOICE] audio_send: failed pcm_len=%d", (int)pcm_len);
        return GPTNIX_WATCHER_VOICE_RESULT_WS_SEND_FAILED;
    }
    return GPTNIX_WATCHER_VOICE_RESULT_OK;
}

/* M3C runtime audio bridge (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md). Handles a fully-reassembled WS text/
 * binary frame received while state == READY: parses Gemini's serverContent.modelTurn.parts[].inlineData
 * audio chunks, forwards decoded PCM to the audio player (synthesizing a 44-byte WAV header naming the
 * fixed 24kHz/16-bit/mono output rate on the FIRST chunk of a stream, matching app_audio_player's own
 * WAV-detection contract -- avoids touching the shared TX/RX I2S/codec clock directly), and finishes the
 * player stream on serverContent.turnComplete. Never logs raw JSON/audio content -- only structural,
 * non-secret integers (parsed/found-part-count/turnComplete booleans, byte counts). Never changes
 * ctx->state -- a malformed/unexpected serverContent shape is silently ignored (diagnostics-only; matches
 * this module's general contract that runtime audio issues are non-fatal to the underlying WS session). */
static void s_handle_ready_server_content(struct app_gptnix_watcher_voice *ctx, cJSON *reply, bool full_consumption)
{
    (void)ctx;
    int audio_parts_found = 0;
    bool turn_complete = false;

    if (full_consumption && reply != NULL && cJSON_IsObject(reply)) {
        cJSON *server_content = cJSON_GetObjectItemCaseSensitive(reply, "serverContent");
        if (cJSON_IsObject(server_content)) {
            cJSON *tc = cJSON_GetObjectItemCaseSensitive(server_content, "turnComplete");
            turn_complete = cJSON_IsBool(tc) && cJSON_IsTrue(tc);

            cJSON *model_turn = cJSON_GetObjectItemCaseSensitive(server_content, "modelTurn");
            cJSON *parts = cJSON_IsObject(model_turn)
                ? cJSON_GetObjectItemCaseSensitive(model_turn, "parts") : NULL;
            if (cJSON_IsArray(parts) && s_audio_cb != NULL) {
                cJSON *part = NULL;
                cJSON_ArrayForEach(part, parts) {
                    if (!cJSON_IsObject(part)) continue;
                    cJSON *inline_data = cJSON_GetObjectItemCaseSensitive(part, "inlineData");
                    if (!cJSON_IsObject(inline_data)) continue;
                    cJSON *data_item = cJSON_GetObjectItemCaseSensitive(inline_data, "data");
                    if (!cJSON_IsString(data_item) || data_item->valuestring == NULL) continue;

                    size_t b64_in_len = strlen(data_item->valuestring);
                    if (b64_in_len == 0 || b64_in_len > GPTNIX_WATCHER_VOICE_AUDIO_CHUNK_MAX_BYTES) continue;
                    audio_parts_found++;

                    size_t pcm_cap = 0;
                    mbedtls_base64_decode(NULL, 0, &pcm_cap,
                        (const uint8_t *)data_item->valuestring, b64_in_len);
                    if (pcm_cap == 0 || pcm_cap > GPTNIX_WATCHER_VOICE_AUDIO_CHUNK_MAX_BYTES) continue;

                    uint8_t *pcm_buf = (uint8_t *)heap_caps_malloc(pcm_cap, MALLOC_CAP_SPIRAM);
                    if (pcm_buf == NULL) continue;

                    size_t pcm_len = 0;
                    int dec_err = mbedtls_base64_decode(pcm_buf, pcm_cap, &pcm_len,
                        (const uint8_t *)data_item->valuestring, b64_in_len);
                    if (dec_err == 0) {
                        s_audio_cb(pcm_buf, pcm_len, false, s_audio_cb_user_data);
                    }
                    free(pcm_buf);
                }
            }
        }
    }

    if (turn_complete && s_audio_cb != NULL) {
        s_audio_cb(NULL, 0, true, s_audio_cb_user_data);
    }

    ESP_LOGI(TAG, "[V2_WATCHER_VOICE] server_content: full=%d parts=%d turn_complete=%d",
        (int)full_consumption, audio_parts_found, (int)turn_complete);
}

static void s_ws_event_handler(void *handler_args,
                                esp_event_base_t base,
                                int32_t event_id,
                                void *event_data)
{
    (void)base;
    struct app_gptnix_watcher_voice *ctx = (struct app_gptnix_watcher_voice *)handler_args;
    if (ctx == NULL) {
        return;
    }
    esp_websocket_event_data_t *data = (esp_websocket_event_data_t *)event_data;

    switch (event_id) {
    case WEBSOCKET_EVENT_CONNECTED: {
        if (ctx->state != GPTNIX_WATCHER_VOICE_STATE_CONNECTING) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        ESP_LOGI(TAG, "[V2_WATCHER_VOICE] ws_state: connected");
        int sent = esp_websocket_client_send_text(
            ctx->ws_client, ctx->setup_json, (int)ctx->setup_json_len,
            pdMS_TO_TICKS(GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS));
        if (sent != (int)ctx->setup_json_len) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_SEND_FAILED;
            break;
        }
        ctx->state = GPTNIX_WATCHER_VOICE_STATE_SETUP_SENT;
        ESP_LOGI(TAG, "[V2_WATCHER_VOICE] ws_state: setup_sent");
        break;
    }

    case WEBSOCKET_EVENT_DATA: {
        // M3B diagnostic (plans/M3B_GEMINI_AUTHTOKEN_SCHEMA_CHILD_TASK.md follow-up): fires before ANY of
        // the validation checks below, since several early `break`s can exit before the setup_reply
        // diagnostic (added further down) is ever reached. Logs only non-secret frame metadata (state
        // enum value, byte counts, fin/opcode) -- never the raw payload content.
        ESP_LOGI(TAG, "[V2_WATCHER_VOICE] ws_data: state=%d null=%d op=%d fin=%d plen=%d poff=%d dlen=%d",
            (int)ctx->state, (int)(data == NULL),
            data ? (int)data->op_code : -1, data ? (int)data->fin : -1,
            data ? (int)data->payload_len : -1, data ? (int)data->payload_offset : -1,
            data ? (int)data->data_len : -1);
        if (data == NULL) break;

        // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with a
        // long-lived READY session revealed WS control frames (ping=0x9, pong=0xA, close=0x8) arriving
        // through this same WEBSOCKET_EVENT_DATA path -- the pre-existing opcode check (0x01/0x02 only,
        // for application-data frames) misclassified every keepalive pong as a protocol error, silently
        // breaking every session shortly after reaching READY. Never proven with a long-lived connection
        // before this session (the M3A diagnostic canary always disconnected within seconds of READY).
        // Control frames carry no application data and never affect ctx->state or the reassembly buffer.
        if (data->op_code == 0x08 /* close */ || data->op_code == 0x09 /* ping */
            || data->op_code == 0x0A /* pong */) {
            break;
        }

        // M3C (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): READY-state frames are no longer ignored -- they
        // carry Gemini's spoken audio response (serverContent.modelTurn.parts[].inlineData), handled by
        // s_handle_ready_server_content() further below. The reassembly logic (identical for both states)
        // is shared; only the FINAL JSON-shape interpretation differs between SETUP_SENT and READY.
        if (ctx->state != GPTNIX_WATCHER_VOICE_STATE_SETUP_SENT
            && ctx->state != GPTNIX_WATCHER_VOICE_STATE_READY) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        if (data->payload_len <= 0 || data->payload_len > GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        if (data->payload_offset < 0 || data->data_len < 0) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }

        if (data->payload_offset == 0) {
            // M3B fix (plans/M3B_GEMINI_AUTHTOKEN_SCHEMA_CHILD_TASK.md follow-up): the original assumption
            // that Gemini's setupComplete reply arrives as a WS TEXT frame (opcode 0x01) only was never
            // proven against the real live API (M2 had no prior physical proof). A live physical attempt,
            // once M3B's other root causes were fixed, showed Gemini actually sends it as a BINARY frame
            // (opcode 0x02) -- proven via the ws_data diagnostic (opcode value logged, non-secret). The
            // payload itself is still parsed identically either way (UTF-8 JSON text, decoded via cJSON) --
            // only the WS framing opcode differs, so both are accepted for this JSON-parsing path.
            if (data->op_code != 0x01 /* WS text frame opcode */ && data->op_code != 0x02 /* WS binary frame opcode */) {
                ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
                ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
                break;
            }
            ctx->rx_accumulated = 0;
            ctx->rx_payload_len = data->payload_len;
        } else if (data->payload_len != ctx->rx_payload_len || data->payload_offset != ctx->rx_accumulated) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }

        if ((size_t)data->data_len > (size_t)(GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES - ctx->rx_accumulated)
            || ctx->rx_accumulated + data->data_len > ctx->rx_payload_len) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }

        if (data->data_len > 0 && data->data_ptr != NULL) {
            memcpy(ctx->rx_buf + ctx->rx_accumulated, data->data_ptr, (size_t)data->data_len);
        }
        ctx->rx_accumulated += data->data_len;

        // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with real speech
        // proved `data->fin` reflects the underlying WS FRAME's own FIN bit (1 for any single,
        // non-WS-fragmented frame Gemini sends -- confirmed against the real esp_websocket_client.h
        // source), NOT whether esp_websocket_client's internal buffer-driven chunked delivery (payload_
        // offset/payload_len, used when a payload exceeds the library's own internal buffer -- see its
        // own header: "payloads exceeding buffer will be posted through multiple events") has finished.
        // Every observed real (large) Gemini reply arrived as multiple same-fin=1 chunks, so the OLD
        // `if (!data->fin) break;` check never actually waited for later chunks -- it silently proceeded
        // to validate an INCOMPLETE reassembly against rx_payload_len on the very first chunk, which
        // could only ever pass by coincidence (a message small enough to arrive in exactly one chunk).
        // The correct signal is the accumulated-vs-total-length comparison, exactly as the header
        // describes.
        if (ctx->rx_accumulated < ctx->rx_payload_len) {
            break; /* wait for more chunks */
        }
        if (ctx->rx_accumulated != ctx->rx_payload_len) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        if ((size_t)ctx->rx_accumulated >= GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES) {
            /* Defensive: cannot NUL-terminate past the buffer bound. */
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        if (memchr(ctx->rx_buf, '\0', (size_t)ctx->rx_accumulated) != NULL) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
            ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            break;
        }
        /* Bounds already proven above (rx_accumulated < buffer size) --
         * terminate only now, as required. */
        ctx->rx_buf[ctx->rx_accumulated] = '\0';

        {
            const char *parse_end = NULL;
            cJSON *reply = cJSON_ParseWithLengthOpts(
                (const char *)ctx->rx_buf, (size_t)ctx->rx_accumulated + 1, &parse_end, 1);
            bool full_consumption = (reply != NULL)
                && (parse_end == (const char *)ctx->rx_buf + ctx->rx_accumulated);

            // M3C: captured BEFORE any further processing below can change ctx->state, since the two
            // states share this same reassembly block but need different JSON-shape interpretations.
            bool was_ready = (ctx->state == GPTNIX_WATCHER_VOICE_STATE_READY);
            if (was_ready) {
                s_handle_ready_server_content(ctx, reply, full_consumption);
                if (reply != NULL) {
                    cJSON_Delete(reply);
                }
                mbedtls_platform_zeroize(ctx->rx_buf, sizeof(ctx->rx_buf));
                ctx->rx_accumulated = 0;
                ctx->rx_payload_len = 0;
                break;
            }

            bool is_setup_complete = false;
            int key_count = 0;
            bool has_setup_complete_key = false;

            if (full_consumption && cJSON_IsObject(reply)) {
                cJSON *child = NULL;
                cJSON_ArrayForEach(child, reply) {
                    key_count++;
                    if (child->string != NULL && strcmp(child->string, "setupComplete") == 0
                        && cJSON_IsObject(child) && child->child == NULL) {
                        /* Locked contract accepts ONLY {"setupComplete":{}} --
                         * cJSON_IsObject rejects arrays/null/scalars, and
                         * child->child == NULL proves the object has zero
                         * members (an object with any key has a non-NULL
                         * ->child pointing at its first member). */
                        has_setup_complete_key = true;
                    }
                }
                is_setup_complete = (key_count == 1) && has_setup_complete_key;
            }
            // M3B diagnostic (plans/M3B_GEMINI_AUTHTOKEN_SCHEMA_CHILD_TASK.md follow-up): the setup-response
            // acceptance contract is locked to EXACTLY {"setupComplete":{}} -- if Gemini's current response
            // shape has drifted (extra/renamed keys), this fires silently as a generic PROTOCOL_ERROR with no
            // detail. Logs only structural, non-secret integers: whether parsing/full-consumption succeeded,
            // key count, and whether the setupComplete key was found -- never the raw JSON content.
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE] setup_reply: parsed=%d full=%d obj=%d keys=%d has_sc=%d",
                (int)(reply != NULL), (int)full_consumption, (int)(full_consumption && cJSON_IsObject(reply)),
                key_count, (int)has_setup_complete_key);
            if (reply != NULL) {
                cJSON_Delete(reply);
            }

            mbedtls_platform_zeroize(ctx->rx_buf, sizeof(ctx->rx_buf));
            ctx->rx_accumulated = 0;
            ctx->rx_payload_len = 0;

            if (is_setup_complete) {
                ctx->state = GPTNIX_WATCHER_VOICE_STATE_READY;
                ESP_LOGI(TAG, "[V2_WATCHER_VOICE] ws_state: ready");
            } else {
                ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
                ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
            }
        }
        break;
    }

    case WEBSOCKET_EVENT_ERROR: {
        ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR;
        int err_type = 0;
        int status = 0;
        if (data != NULL) {
            err_type = (int)data->error_handle.error_type;
            status = data->error_handle.esp_ws_handshake_status_code;
        }
        ESP_LOGW(TAG, "[V2_WATCHER_VOICE] ws_error: type=%d status=%d", err_type, status);
        break;
    }

    case WEBSOCKET_EVENT_CLOSED:
    case WEBSOCKET_EVENT_DISCONNECTED: {
        if (ctx->state != GPTNIX_WATCHER_VOICE_STATE_ERROR) {
            ctx->state = GPTNIX_WATCHER_VOICE_STATE_CLOSED;
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE] ws_state: closed");
        }
        /* No auto reconnect: disable_auto_reconnect=true in config, and this
         * handler never creates another client. */
        break;
    }

    default:
        break;
    }
}

#else /* !CONFIG_GPTNIX_WATCHER_VOICE */

esp_err_t app_gptnix_watcher_voice_init(void)
{
    return ESP_OK;
}

esp_err_t app_gptnix_watcher_voice_deinit(void)
{
    return ESP_OK;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_prepare_session(
    const char *session_json,
    size_t session_len)
{
    (void)session_json;
    (void)session_len;
    return GPTNIX_WATCHER_VOICE_RESULT_DISABLED;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_connect(void)
{
    return GPTNIX_WATCHER_VOICE_RESULT_DISABLED;
}

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_disconnect(void)
{
    return GPTNIX_WATCHER_VOICE_RESULT_DISABLED;
}

app_gptnix_watcher_voice_state_t app_gptnix_watcher_voice_get_state(void)
{
    return GPTNIX_WATCHER_VOICE_STATE_UNINITIALIZED;
}

#endif /* CONFIG_GPTNIX_WATCHER_VOICE */
