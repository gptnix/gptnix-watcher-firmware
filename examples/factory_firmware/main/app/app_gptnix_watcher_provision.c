/**
 * GPTNiX Watcher M3A host-controlled provisioning canary.
 *
 * See app_gptnix_watcher_provision.h for the public contract. This module owns
 * the GPTNIX_WATCHER_M3A_PROVISION_V1 wire protocol (magic "GNX3", version 1,
 * 8-byte header, 1..4096-byte TOKEN_FRAME payload, five message types) exactly
 * as locked by the backend addendum, and the device-side
 * TOKEN_FRAME -> TOKEN_STAGED -> PROVISION_COMMIT handoff state machine.
 *
 * Secret-lifetime discipline: the staged Firebase device ID token exists ONLY
 * as one PSRAM-owned buffer (read directly off the UART -- never a second raw
 * payload copy) and, transiently, inside one PSRAM-owned "Bearer <token>"
 * Authorization buffer built for the single HTTPS POST. Both are zeroized via
 * mbedtls_platform_zeroize() and freed on every terminal path, including every
 * pre-COMMIT failure branch (ABORT / commit timeout / malformed frame). The
 * token is never written to NVS, never logged, never placed in a URL, and
 * never reaches console argv/linenoise/history -- this module only ever reads
 * raw bytes directly off CONFIG_ESP_CONSOLE_UART_NUM via uart_read_bytes(),
 * strictly before app_cmd_start_repl() has woken the REPL/linenoise task (see
 * app_cmd.c's app_cmd_prepare_repl()/app_cmd_start_repl() split).
 *
 * Session POST is reachable ONLY after a valid PROVISION_COMMIT is received --
 * SESSION_POST_BEFORE_PROVISION_COMMIT_POSSIBLE=false is enforced structurally:
 * the one HTTP POST call site in this file is reached only after
 * s_wait_for_commit_or_abort() has already returned OK.
 *
 * Third-party transport memory note: the raw UART driver ring and the
 * esp_http_client/esp_websocket_client internal buffers are owned and freed by
 * those libraries themselves; this module never claims to zeroize bytes it
 * does not itself own a copy of.
 */
#include "app_gptnix_watcher_provision.h"
#include "sdkconfig.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/platform_util.h"

#if CONFIG_GPTNIX_WATCHER_PROVISION

#include <stdio.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include <time.h>

#include "driver/uart.h"

#include "app_gptnix_watcher_voice.h"
#include "app_gptnix_watcher_voice_runtime.h"

static const char *TAG = "V2_WATCHER_PROVISION";

/* ---------------------------------------------------------------------------
 * GPTNIX_WATCHER_M3A_PROVISION_V1 protocol constants -- must match the backend
 * addendum exactly. Do not introduce a different firmware protocol version.
 * ------------------------------------------------------------------------- */
#define GW_M3A_MAGIC_0     'G'
#define GW_M3A_MAGIC_1     'N'
#define GW_M3A_MAGIC_2     'X'
#define GW_M3A_MAGIC_3     '3'
#define GW_M3A_VERSION     0x01
#define GW_M3A_HEADER_BYTES 8
#define GW_M3A_MAX_PAYLOAD_BYTES 4096

#define GW_M3A_MSG_BRIDGE_READY      0x01
#define GW_M3A_MSG_TOKEN_FRAME       0x02
#define GW_M3A_MSG_TOKEN_STAGED      0x03
#define GW_M3A_MSG_PROVISION_COMMIT  0x04
#define GW_M3A_MSG_PROVISION_ABORT   0x05

/* Bounded time budgets -- no infinite wait anywhere in this module. */
#define GW_TOKEN_FRAME_WAIT_MS   60000
#define GW_COMMIT_WAIT_MS        15000
#define GW_IP_WAIT_MS            30000
#define GW_HTTP_TIMEOUT_MS       10000
#define GW_VOICE_READY_TIMEOUT_MS 20000
#define GW_SESSION_RESPONSE_MAX_BYTES 65536

#define GW_SESSION_URL_MAX_LEN 512
static const char GW_SESSION_URL_SUFFIX[] = "/v2/watcher/realtime/session";

/* ---------------------------------------------------------------------------
 * Bounded raw UART frame I/O over the console UART already installed by
 * app_cmd_prepare_repl() (never a second driver install). One monotonic
 * deadline per logical read; s_uart_read_exact() never busy-waits past it.
 * ------------------------------------------------------------------------- */

static esp_err_t s_uart_read_exact(uint8_t *dst, size_t len, TickType_t deadline_ticks)
{
    size_t got = 0;
    while (got < len) {
        TickType_t now = xTaskGetTickCount();
        if (now >= deadline_ticks) {
            return ESP_ERR_TIMEOUT;
        }
        int n = uart_read_bytes(CONFIG_ESP_CONSOLE_UART_NUM, dst + got, len - got, deadline_ticks - now);
        if (n < 0) {
            return ESP_FAIL;
        }
        got += (size_t)n;
    }
    return ESP_OK;
}

static esp_err_t s_uart_write_exact(const uint8_t *src, size_t len)
{
    int n = uart_write_bytes(CONFIG_ESP_CONSOLE_UART_NUM, (const char *)src, len);
    if (n < 0 || (size_t)n != len) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

typedef struct {
    uint8_t type;
    uint16_t payload_len;
} gw_frame_header_t;

// Reads and validates exactly one 8-byte frame header (magic/version/type/length). Never reads a payload --
// callers decide whether/how much payload to read based on the parsed type. Never logs the raw header bytes.
static esp_err_t s_read_frame_header(gw_frame_header_t *out, TickType_t deadline_ticks)
{
    uint8_t header[GW_M3A_HEADER_BYTES];
    esp_err_t err = s_uart_read_exact(header, sizeof(header), deadline_ticks);
    if (err != ESP_OK) {
        return err;
    }
    if (header[0] != GW_M3A_MAGIC_0 || header[1] != GW_M3A_MAGIC_1 || header[2] != GW_M3A_MAGIC_2 || header[3] != GW_M3A_MAGIC_3) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (header[4] != GW_M3A_VERSION) {
        return ESP_ERR_INVALID_VERSION;
    }
    out->type = header[5];
    out->payload_len = (uint16_t)(((uint16_t)header[6] << 8) | (uint16_t)header[7]);
    return ESP_OK;
}

// Writes exactly one bounded, zero-payload control frame. Never called for TOKEN_FRAME (device only RECEIVES
// TOKEN_FRAME, never sends one). Contains no secret -- not printed as text, one bounded write call.
static esp_err_t s_write_control_frame(uint8_t type)
{
    uint8_t frame[GW_M3A_HEADER_BYTES] = {
        GW_M3A_MAGIC_0, GW_M3A_MAGIC_1, GW_M3A_MAGIC_2, GW_M3A_MAGIC_3,
        GW_M3A_VERSION, type, 0, 0,
    };
    return s_uart_write_exact(frame, sizeof(frame));
}

/* ---------------------------------------------------------------------------
 * D5 -- TOKEN_FRAME receive: exact 8-byte header, magic/version/type validated,
 * payload length 1..4096, payload read DIRECTLY into a single PSRAM-owned
 * device token buffer (payloadLength+1, NUL-terminated), embedded NUL/CR/LF
 * rejected, bytes never logged.
 * ------------------------------------------------------------------------- */
static app_gptnix_watcher_provision_result_t s_receive_token_frame(
    uint32_t timeout_ms, uint8_t **out_token, size_t *out_token_len)
{
    *out_token = NULL;
    *out_token_len = 0;

    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);

    gw_frame_header_t hdr;
    esp_err_t err = s_read_frame_header(&hdr, deadline);
    if (err == ESP_ERR_TIMEOUT) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_TIMEOUT;
    }
    if (err != ESP_OK) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    if (hdr.type != GW_M3A_MSG_TOKEN_FRAME) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    if (hdr.payload_len < 1 || hdr.payload_len > GW_M3A_MAX_PAYLOAD_BYTES) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }

    uint8_t *token_buf = (uint8_t *)heap_caps_malloc((size_t)hdr.payload_len + 1, MALLOC_CAP_SPIRAM);
    if (token_buf == NULL) {
        return GPTNIX_WATCHER_PROVISION_RESULT_NO_MEMORY;
    }

    err = s_uart_read_exact(token_buf, (size_t)hdr.payload_len, deadline);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(token_buf, (size_t)hdr.payload_len + 1);
        free(token_buf);
        return (err == ESP_ERR_TIMEOUT)
            ? GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_TIMEOUT
            : GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    token_buf[hdr.payload_len] = '\0';

    for (uint16_t i = 0; i < hdr.payload_len; i++) {
        uint8_t b = token_buf[i];
        if (b == '\0' || b == '\r' || b == '\n') {
            mbedtls_platform_zeroize(token_buf, (size_t)hdr.payload_len + 1);
            free(token_buf);
            return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
        }
    }

    *out_token = token_buf;
    *out_token_len = (size_t)hdr.payload_len;
    return GPTNIX_WATCHER_PROVISION_RESULT_OK;
}

/* ---------------------------------------------------------------------------
 * D7 -- TOKEN_STAGED already sent by the caller; this reads exactly one next
 * control frame and classifies it. Caller owns token zeroization for every
 * non-OK outcome (ABORT / commit timeout / malformed-unexpected all -> zero
 * session POSTs). No retry.
 * ------------------------------------------------------------------------- */
static app_gptnix_watcher_provision_result_t s_wait_for_commit_or_abort(uint32_t timeout_ms)
{
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);

    gw_frame_header_t hdr;
    esp_err_t err = s_read_frame_header(&hdr, deadline);
    if (err == ESP_ERR_TIMEOUT) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_TIMEOUT;
    }
    if (err != ESP_OK) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    if (hdr.payload_len != 0) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    if (hdr.type == GW_M3A_MSG_PROVISION_ABORT) {
        return GPTNIX_WATCHER_PROVISION_RESULT_ABORTED;
    }
    if (hdr.type == GW_M3A_MSG_PROVISION_COMMIT) {
        return GPTNIX_WATCHER_PROVISION_RESULT_OK;
    }
    return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
}

/* ---------------------------------------------------------------------------
 * D8 -- session URL config validation. Runs BEFORE any UART/network activity
 * so a misconfigured build fails closed without ever staging a secret or
 * running the wire handshake.
 * ------------------------------------------------------------------------- */
static bool s_session_url_valid(const char *url)
{
    if (url == NULL) {
        return false;
    }
    size_t len = strlen(url);
    if (len == 0 || len > GW_SESSION_URL_MAX_LEN) {
        return false;
    }
    if (strncmp(url, "https://", 8) != 0) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char c = url[i];
        if (c == '\r' || c == '\n' || c == '?' || c == '#') {
            return false;
        }
    }
    size_t suffix_len = sizeof(GW_SESSION_URL_SUFFIX) - 1;
    if (len < suffix_len) {
        return false;
    }
    return strcmp(url + (len - suffix_len), GW_SESSION_URL_SUFFIX) == 0;
}

/* ---------------------------------------------------------------------------
 * D9 -- bounded, provisioning-local Wi-Fi IP readiness waiter. Never modifies
 * app_wifi.c/.h. Registers its OWN event handler instance (never touches
 * app_wifi.c's), and covers both "GOT_IP already happened" (immediate netif
 * inspection) and "GOT_IP happens later" (bounded semaphore wait) -- the
 * handler is registered BEFORE the immediate inspection so no event can be
 * missed in between. Always unregisters/deletes its own private objects
 * before returning, on every path.
 * ------------------------------------------------------------------------- */
typedef struct {
    SemaphoreHandle_t sem;
} gw_wifi_waiter_t;

static void s_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)event_base;
    (void)event_data;
    if (event_id != IP_EVENT_STA_GOT_IP) {
        return;
    }
    gw_wifi_waiter_t *waiter = (gw_wifi_waiter_t *)arg;
    if (waiter != NULL && waiter->sem != NULL) {
        xSemaphoreGive(waiter->sem);
    }
}

static app_gptnix_watcher_provision_result_t s_wait_for_ip(uint32_t timeout_ms)
{
    gw_wifi_waiter_t waiter;
    waiter.sem = xSemaphoreCreateBinary();
    if (waiter.sem == NULL) {
        return GPTNIX_WATCHER_PROVISION_RESULT_NO_MEMORY;
    }

    esp_event_handler_instance_t instance = NULL;
    esp_err_t reg_err = esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &s_ip_event_handler, &waiter, &instance);
    if (reg_err != ESP_OK) {
        vSemaphoreDelete(waiter.sem);
        return GPTNIX_WATCHER_PROVISION_RESULT_WIFI_TIMEOUT;
    }

    app_gptnix_watcher_provision_result_t result = GPTNIX_WATCHER_PROVISION_RESULT_WIFI_TIMEOUT;

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info));
    if (sta_netif != NULL && esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_OK;
    } else if (xSemaphoreTake(waiter.sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_OK;
    }

    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance);
    vSemaphoreDelete(waiter.sem);
    return result;
}

/* ---------------------------------------------------------------------------
 * D10/D11 -- exactly one HTTPS POST, only ever reached after
 * s_wait_for_commit_or_abort() has already returned OK (see the single call
 * site in app_gptnix_watcher_provision_run() below). Bounded response
 * accumulation, pre-copy bound check, no retry, no redirect-following, no
 * body/header logging. Takes ownership of token_buf and zeroizes+frees it
 * immediately after esp_http_client_perform() returns, before any later M2
 * work -- never assumes the HTTP library's own internal header-copy is
 * zeroized (only that it is freed by esp_http_client_cleanup()).
 * ------------------------------------------------------------------------- */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    bool overflow;
} gw_http_response_accumulator_t;

static esp_err_t s_http_event_handler(esp_http_client_event_t *evt)
{
    if (evt->event_id != HTTP_EVENT_ON_DATA) {
        return ESP_OK;
    }
    gw_http_response_accumulator_t *acc = (gw_http_response_accumulator_t *)evt->user_data;
    if (acc == NULL || acc->overflow) {
        return ESP_OK;
    }
    if (acc->len + (size_t)evt->data_len > acc->cap) {
        acc->overflow = true;
        return ESP_OK;
    }
    memcpy(acc->buf + acc->len, evt->data, (size_t)evt->data_len);
    acc->len += (size_t)evt->data_len;
    return ESP_OK;
}

static app_gptnix_watcher_provision_result_t s_do_session_post(
    const char *session_url, uint8_t *token_buf, size_t token_len,
    char **out_response_buf, size_t *out_response_len)
{
    *out_response_buf = NULL;
    *out_response_len = 0;

    static const char BEARER_PREFIX[] = "Bearer ";
    size_t prefix_len = sizeof(BEARER_PREFIX) - 1;
    size_t auth_len = prefix_len + token_len;
    char *auth_value = (char *)heap_caps_malloc(auth_len + 1, MALLOC_CAP_SPIRAM);
    if (auth_value == NULL) {
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        return GPTNIX_WATCHER_PROVISION_RESULT_NO_MEMORY;
    }
    memcpy(auth_value, BEARER_PREFIX, prefix_len);
    memcpy(auth_value + prefix_len, token_buf, token_len);
    auth_value[auth_len] = '\0';

    gw_http_response_accumulator_t acc;
    memset(&acc, 0, sizeof(acc));
    acc.cap = GW_SESSION_RESPONSE_MAX_BYTES;
    acc.buf = (char *)heap_caps_malloc(acc.cap + 1, MALLOC_CAP_SPIRAM);
    if (acc.buf == NULL) {
        mbedtls_platform_zeroize(auth_value, auth_len + 1);
        free(auth_value);
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        return GPTNIX_WATCHER_PROVISION_RESULT_NO_MEMORY;
    }

    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] heap: stage=before_http internal=%u psram=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    esp_http_client_config_t config;
    memset(&config, 0, sizeof(config));
    config.url = session_url;
    config.method = HTTP_METHOD_POST;
    config.timeout_ms = GW_HTTP_TIMEOUT_MS;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.event_handler = s_http_event_handler;
    config.user_data = &acc;
    config.disable_auto_redirect = true;
    // M3B fix (plans/M3B_HTTP_BUFFER_TX_CHILD_TASK.md): esp_http_client's default TX buffer
    // (DEFAULT_HTTP_BUF_SIZE, 512 bytes) is too small to hold the full request header block in one pass --
    // the Authorization header alone (a Firebase ID token JWT) is typically 800-1500+ bytes. Proven via a
    // live device capture (nginx debug log, operator-authorized): the device sent only the first ~133
    // bytes of headers, stalled for exactly GW_HTTP_TIMEOUT_MS, then closed the connection itself
    // ("client prematurely closed connection while reading client request headers"). Sized generously
    // above any realistic single-header size, not to the exact observed minimum.
    config.buffer_size_tx = 4096;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        mbedtls_platform_zeroize(auth_value, auth_len + 1);
        free(auth_value);
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        mbedtls_platform_zeroize(acc.buf, acc.cap + 1);
        free(acc.buf);
        return GPTNIX_WATCHER_PROVISION_RESULT_HTTP_INIT_FAILED;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Authorization", auth_value);
    esp_http_client_set_post_field(client, "{}", 2);

    // One call site, no retry: exactly one esp_http_client_perform() per provisioning run, only ever reached
    // after COMMIT (see the single call site of this function below).
    // M3B diagnostic (plans/M3B_HTTP_BUFFER_TX_CHILD_TASK.md follow-up): buffer_size_tx and task stack
    // size fixes did not resolve the session-POST stall -- logging the exact esp_err_t name and elapsed
    // wall-clock time to distinguish a real ~10s client-side timeout from a faster, differently-classed
    // failure. Never logs secret content, only a fixed non-secret error name string and an integer ms count.
    // Time-desync diagnostic (2026-08-23 follow-up): a live physical test showed a consistent, fast
    // (90-180ms) ESP_ERR_HTTP_CONNECT failure connecting to a domain independently confirmed reachable
    // (valid Lets Encrypt cert, correct DNS) from the same WiFi network via a phone browser -- suspected
    // cause is TLS certificate time-validity failing because SNTP has not yet completed syncing this early
    // in boot. Logs only the device's own Unix timestamp (a non-secret integer) immediately before the
    // HTTPS call, to prove or rule this out with real data instead of guessing further.
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] clock: unix_time=%lld", (long long)time(NULL));
    int64_t perform_start_us = esp_timer_get_time();
    esp_err_t perform_err = esp_http_client_perform(client);
    int64_t perform_elapsed_ms = (esp_timer_get_time() - perform_start_us) / 1000;
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] http_perform: err=%d elapsed_ms=%lld",
        (int)perform_err, (long long)perform_elapsed_ms);
    int status = (perform_err == ESP_OK) ? esp_http_client_get_status_code(client) : -1;
    // M3B diagnostic (plans/M3B_HTTP_BUFFER_TX_CHILD_TASK.md follow-up): status/overflow/len are all
    // non-secret integers -- needed now that perform_err alone (ESP_OK) no longer distinguishes the
    // actual failure branch below.
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] http_status: code=%d", status);

    // Immediately after perform() returns: zeroize the auth buffer and the staged ID token, before any later
    // M2/WSS work -- never deferred, regardless of the outcome below.
    mbedtls_platform_zeroize(auth_value, auth_len + 1);
    free(auth_value);
    mbedtls_platform_zeroize(token_buf, token_len + 1);
    free(token_buf);

    esp_http_client_cleanup(client);

    app_gptnix_watcher_provision_result_t result;
    if (perform_err != ESP_OK) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_HTTP_FAILED;
    } else if (status == 401 || status == 403) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_HTTP_UNAUTHORIZED;
    } else if (acc.overflow) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_HTTP_RESPONSE_TOO_LARGE;
    } else if (status != 200 || acc.len == 0) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_HTTP_FAILED;
    } else {
        acc.buf[acc.len] = '\0';
        *out_response_buf = acc.buf;
        *out_response_len = acc.len;
        return GPTNIX_WATCHER_PROVISION_RESULT_OK; // acc.buf ownership transfers to the caller
    }

    mbedtls_platform_zeroize(acc.buf, acc.cap + 1);
    free(acc.buf);
    return result;
}

/* ---------------------------------------------------------------------------
 * D12/D13 -- M2 handoff: the accumulated 200 response goes verbatim to
 * app_gptnix_watcher_voice_prepare_session() exactly once; M2 remains the sole
 * DTO validator. Exactly one prepare_session call site, one connect call site,
 * bounded get_state() poll for READY, terminal disconnect()/deinit() exactly
 * once on every reachable path from prepare_session() onward. This module
 * never calls esp_websocket_client_* directly.
 * ------------------------------------------------------------------------- */
// Takes ownership of response_buf (caller-allocated, PSRAM, response_len bytes + NUL): zeroized and freed
// HERE, immediately after prepare_session() settles (success or failure), per D12 -- never held alive through
// connect()/READY-wait, even though M2's own prepare_session() has already made its own internal copy.
static app_gptnix_watcher_provision_result_t s_hand_off_to_voice(char *response_buf, size_t response_len)
{
    app_gptnix_watcher_provision_result_t result = GPTNIX_WATCHER_PROVISION_RESULT_VOICE_RUNTIME_ERROR;

    esp_err_t init_err = app_gptnix_watcher_voice_init();
    if (init_err != ESP_OK) {
        mbedtls_platform_zeroize(response_buf, response_len + 1);
        free(response_buf);
        return GPTNIX_WATCHER_PROVISION_RESULT_VOICE_INIT_FAILED; // never connected -- nothing to disconnect
    }

    app_gptnix_watcher_voice_result_t prep = app_gptnix_watcher_voice_prepare_session(response_buf, response_len);
    // Immediately after prepare_session() settles: zeroize + free the response buffer, before any connect()/
    // WSS work -- M2's own prepare_session() has already made whatever internal copy it needs.
    mbedtls_platform_zeroize(response_buf, response_len + 1);
    free(response_buf);
    response_buf = NULL;
    if (prep != GPTNIX_WATCHER_VOICE_RESULT_OK) {
        result = GPTNIX_WATCHER_PROVISION_RESULT_VOICE_PREPARE_FAILED;
        goto cleanup;
    }

    {
        app_gptnix_watcher_voice_result_t conn = app_gptnix_watcher_voice_connect();
        if (conn != GPTNIX_WATCHER_VOICE_RESULT_OK) {
            result = GPTNIX_WATCHER_PROVISION_RESULT_VOICE_CONNECT_FAILED;
            goto cleanup;
        }
    }

    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] heap: stage=before_ws internal=%u psram=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    {
        TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(GW_VOICE_READY_TIMEOUT_MS);
        for (;;) {
            app_gptnix_watcher_voice_state_t state = app_gptnix_watcher_voice_get_state();
            if (state == GPTNIX_WATCHER_VOICE_STATE_READY) {
                ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] voice: ready");
                result = GPTNIX_WATCHER_PROVISION_RESULT_OK;
                break;
            }
            if (state == GPTNIX_WATCHER_VOICE_STATE_ERROR || state == GPTNIX_WATCHER_VOICE_STATE_CLOSED) {
                result = GPTNIX_WATCHER_PROVISION_RESULT_VOICE_RUNTIME_ERROR;
                break;
            }
            if (xTaskGetTickCount() >= deadline) {
                result = GPTNIX_WATCHER_PROVISION_RESULT_VOICE_READY_TIMEOUT;
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

#if CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME
    // M3C (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): unlike the M3A diagnostic canary's connect-then-
    // disconnect behavior (the `cleanup:` path below, still used for every OTHER outcome and whenever
    // this config is off), a successful READY session is kept alive here -- the WSS client is NOT
    // disconnected/deinitialized, and the mic-feeding task takes over sending audio. Returns directly,
    // skipping `cleanup:` entirely, since the voice module's own lifetime now outlives this function.
    if (result == GPTNIX_WATCHER_PROVISION_RESULT_OK) {
        app_gptnix_watcher_voice_runtime_start();
        ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] audio_bridge: started");
        return result;
    }
#endif

cleanup:
    // Terminal cleanup, exactly once, on every path reached from prepare_session() onward. M2's disconnect()/
    // deinit() both tolerate being called even when connect() never started a client (see
    // app_gptnix_watcher_voice.c) -- M3A.3B proves transport only, so the WSS client is intentionally cleaned
    // up here rather than left running for audio.
    app_gptnix_watcher_voice_disconnect();
    app_gptnix_watcher_voice_deinit();

    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] heap: stage=after_cleanup internal=%u psram=%u",
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL), (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    return result;
}

/* ---------------------------------------------------------------------------
 * Core provisioning cycle (D2-D14). Called only from the public entry point
 * below, which always flushes the console UART's RX buffer afterward -- see
 * app_gptnix_watcher_provision_run().
 * ------------------------------------------------------------------------- */
static app_gptnix_watcher_provision_result_t s_run_provision_cycle(void)
{
    const char *session_url = CONFIG_GPTNIX_WATCHER_SESSION_URL;
    if (!s_session_url_valid(session_url)) {
        return GPTNIX_WATCHER_PROVISION_RESULT_INVALID_CONFIG;
    }

    esp_err_t frame_err = s_write_control_frame(GW_M3A_MSG_BRIDGE_READY);
    if (frame_err != ESP_OK) {
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] bridge: ready");

    uint8_t *token_buf = NULL;
    size_t token_len = 0;
    app_gptnix_watcher_provision_result_t result =
        s_receive_token_frame(GW_TOKEN_FRAME_WAIT_MS, &token_buf, &token_len);
    if (result != GPTNIX_WATCHER_PROVISION_RESULT_OK) {
        return result; // no token was ever staged -- nothing to zeroize
    }

    frame_err = s_write_control_frame(GW_M3A_MSG_TOKEN_STAGED);
    if (frame_err != ESP_OK) {
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] token: staged");

    result = s_wait_for_commit_or_abort(GW_COMMIT_WAIT_MS);
    if (result != GPTNIX_WATCHER_PROVISION_RESULT_OK) {
        // ABORTED / TRANSPORT_TIMEOUT / TRANSPORT_PROTOCOL_ERROR -- zero session POSTs on every branch.
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        return result;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] commit: accepted");
    /* ---- COMMIT boundary: the session POST below is reachable ONLY from this line forward. ---- */

    result = s_wait_for_ip(GW_IP_WAIT_MS);
    if (result != GPTNIX_WATCHER_PROVISION_RESULT_OK) {
        mbedtls_platform_zeroize(token_buf, token_len + 1);
        free(token_buf);
        return result;
    }

    char *response_buf = NULL;
    size_t response_len = 0;
    // s_do_session_post() takes ownership of token_buf and zeroizes+frees it internally.
    result = s_do_session_post(session_url, token_buf, token_len, &response_buf, &response_len);
    token_buf = NULL;
    if (result != GPTNIX_WATCHER_PROVISION_RESULT_OK) {
        return result;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] session: http_200");

    // s_hand_off_to_voice() takes ownership of response_buf and zeroizes+frees it internally, immediately
    // after prepare_session() settles (before connect()/READY-wait) -- see its own header comment.
    result = s_hand_off_to_voice(response_buf, response_len);

    return result;
}

/* ---------------------------------------------------------------------------
 * Public entry point. Must be called between app_cmd_prepare_repl() and
 * app_cmd_start_repl() -- see main.c. This is the ONE canonical point that
 * logs a terminal classified result for every active-feature outcome (early
 * config/transport/commit/Wi-Fi/HTTP/voice failures included, not just the
 * successful tail) -- s_run_provision_cycle() itself logs no terminal result.
 * Unconditionally flushes the console UART's RX buffer before returning, on
 * every outcome: any bytes still sitting in the driver ring at this point
 * are, by construction, either already-consumed protocol framing (never
 * secret -- the staged token is already zeroized well before this point on
 * every path) or unexpected noise, and must never be allowed to leak into
 * the REPL/linenoise session app_cmd_start_repl() is about to wake.
 * ------------------------------------------------------------------------- */
app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void)
{
    app_gptnix_watcher_provision_result_t result = s_run_provision_cycle();
    ESP_LOGI(TAG, "[V2_WATCHER_PROVISION] terminal: code=%d", (int)result);
    uart_flush_input(CONFIG_ESP_CONSOLE_UART_NUM);
    return result;
}

#else /* !CONFIG_GPTNIX_WATCHER_PROVISION */

app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void)
{
    return GPTNIX_WATCHER_PROVISION_RESULT_DISABLED;
}

#endif /* CONFIG_GPTNIX_WATCHER_PROVISION */
