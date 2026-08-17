/**
 * GPTNiX Watcher M3A host-controlled provisioning canary.
 *
 * The ONE device-side orchestration owner for the GPTNIX_WATCHER_M3A_PROVISION_V1
 * pre-REPL raw UART handoff (docs/v2/V2_WATCHER_M3A_PROVISIONING_SESSION_CANARY_
 * ADDENDUM_2026-08-17.md in the backend repo): receives a short-lived Firebase
 * device ID token over the console UART before the REPL task starts, stages it
 * in RAM/PSRAM only (never NVS), blocks on an explicit host PROVISION_COMMIT
 * before ever calling the backend session endpoint, hands the resulting session
 * DTO to the existing M2 voice transport owner (app_gptnix_watcher_voice.*), and
 * cleans the M2 client back up once GPTNiX Gemini Live `READY` is observed --
 * this milestone proves transport only, it does not stream audio.
 *
 * This module is allowed to call the M2 public API. It is NOT a second
 * WebSocket/session owner: it never calls esp_websocket_client_* directly, and
 * main.c never calls app_gptnix_watcher_voice_* directly -- this module is the
 * only runtime caller of both APIs.
 */
#ifndef APP_GPTNIX_WATCHER_PROVISION_H
#define APP_GPTNIX_WATCHER_PROVISION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GPTNIX_WATCHER_PROVISION_RESULT_OK = 0,
    GPTNIX_WATCHER_PROVISION_RESULT_DISABLED,
    GPTNIX_WATCHER_PROVISION_RESULT_INVALID_CONFIG,
    GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_TIMEOUT,
    GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR,
    GPTNIX_WATCHER_PROVISION_RESULT_ABORTED,
    GPTNIX_WATCHER_PROVISION_RESULT_NO_MEMORY,
    GPTNIX_WATCHER_PROVISION_RESULT_WIFI_TIMEOUT,
    GPTNIX_WATCHER_PROVISION_RESULT_HTTP_INIT_FAILED,
    GPTNIX_WATCHER_PROVISION_RESULT_HTTP_UNAUTHORIZED,
    GPTNIX_WATCHER_PROVISION_RESULT_HTTP_FAILED,
    GPTNIX_WATCHER_PROVISION_RESULT_HTTP_RESPONSE_TOO_LARGE,
    GPTNIX_WATCHER_PROVISION_RESULT_VOICE_INIT_FAILED,
    GPTNIX_WATCHER_PROVISION_RESULT_VOICE_PREPARE_FAILED,
    GPTNIX_WATCHER_PROVISION_RESULT_VOICE_CONNECT_FAILED,
    GPTNIX_WATCHER_PROVISION_RESULT_VOICE_READY_TIMEOUT,
    GPTNIX_WATCHER_PROVISION_RESULT_VOICE_RUNTIME_ERROR,
} app_gptnix_watcher_provision_result_t;

/**
 * Runs one synchronous, non-retrying M3A provisioning cycle: emits BRIDGE_READY,
 * receives+stages a TOKEN_FRAME, blocks for PROVISION_COMMIT/PROVISION_ABORT,
 * POSTs the staged token to the configured session endpoint exactly once after
 * COMMIT, hands the response to M2, waits for READY, then disconnects/deinits
 * M2. Must be called between app_cmd_prepare_repl() and app_cmd_start_repl() --
 * see main.c for the exact call order. No token/session getter is exposed;
 * every secret this function stages is zeroized before it returns.
 */
app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_GPTNIX_WATCHER_PROVISION_H */
