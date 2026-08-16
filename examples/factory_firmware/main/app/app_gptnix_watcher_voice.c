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
#include "esp_websocket_client.h"
#include "freertos/FreeRTOS.h"

static const char *TAG = "V2_WATCHER_VOICE";

#define GPTNIX_WATCHER_VOICE_SESSION_DTO_MAX_BYTES   (65536)
#define GPTNIX_WATCHER_VOICE_ENDPOINT_MAX_BYTES      (512)
#define GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES         (2048)
#define GPTNIX_WATCHER_VOICE_SETUP_JSON_MAX_BYTES    (32768)
#define GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES (8192)
#define GPTNIX_WATCHER_VOICE_WS_BUFFER_BYTES         (4096)
#define GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS      (10000)

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
    if (s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_SESSION_READY) {
        return GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT;
    }

    char auth_value[GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES + 8]; /* "Token " + token + NUL */
    int written = snprintf(auth_value, sizeof(auth_value), "Token %s", s_ctx->token);
    if (written < 0 || (size_t)written >= sizeof(auth_value)) {
        mbedtls_platform_zeroize(auth_value, sizeof(auth_value));
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED;
        return s_ctx->last_result;
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
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED;
        return s_ctx->last_result;
    }

    esp_err_t header_err = esp_websocket_client_append_header(s_ctx->ws_client, "Authorization", auth_value);
    /* The library copies this value into its own heap-owned header state
     * during append -- safe to zeroize our temporary copy immediately. */
    mbedtls_platform_zeroize(auth_value, sizeof(auth_value));
    if (header_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED;
        return s_ctx->last_result;
    }

    esp_err_t reg_err = esp_websocket_register_events(
        s_ctx->ws_client, WEBSOCKET_EVENT_ANY, s_ws_event_handler, s_ctx);
    if (reg_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED;
        return s_ctx->last_result;
    }

    s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_CONNECTING;

    esp_err_t start_err = esp_websocket_client_start(s_ctx->ws_client);
    if (start_err != ESP_OK) {
        esp_websocket_client_destroy(s_ctx->ws_client);
        s_ctx->ws_client = NULL;
        s_clear_session_material(s_ctx);
        s_ctx->state = GPTNIX_WATCHER_VOICE_STATE_ERROR;
        s_ctx->last_result = GPTNIX_WATCHER_VOICE_RESULT_WS_START_FAILED;
        return s_ctx->last_result;
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
        if (data == NULL) break;

        if (ctx->state == GPTNIX_WATCHER_VOICE_STATE_READY) {
            /* M2 never processes/logs body content after READY. */
            break;
        }
        if (ctx->state != GPTNIX_WATCHER_VOICE_STATE_SETUP_SENT) {
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
            if (data->op_code != 0x01 /* WS text frame opcode */) {
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

        if (!data->fin) {
            break; /* wait for more fragments */
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
            bool is_setup_complete = false;

            if (full_consumption && cJSON_IsObject(reply)) {
                int key_count = 0;
                bool has_setup_complete_key = false;
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
