/**
 * GPTNiX Watcher realtime-voice WSS transport/session foundation.
 *
 * The ONE canonical firmware owner for the GPTNiX Gemini Live WebSocket
 * transport/session lifecycle. Consumes a backend-provisioned session DTO
 * (see docs/GPTNIX_WATCHER_VOICE_TRANSPORT_CONTRACT_V1.md) and drives the
 * connect -> setup -> setupComplete handshake only.
 *
 * M2 scope: transport/session foundation only. No microphone streaming, no
 * speaker playback, no Firebase/pairing/HTTP bootstrap, no device flash.
 * Runtime camera/audio/backend-call wiring is a separate, later milestone.
 */
#ifndef APP_GPTNIX_WATCHER_VOICE_H
#define APP_GPTNIX_WATCHER_VOICE_H

#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GPTNIX_WATCHER_VOICE_STATE_UNINITIALIZED = 0,
    GPTNIX_WATCHER_VOICE_STATE_IDLE,
    GPTNIX_WATCHER_VOICE_STATE_SESSION_READY,
    GPTNIX_WATCHER_VOICE_STATE_CONNECTING,
    GPTNIX_WATCHER_VOICE_STATE_SETUP_SENT,
    GPTNIX_WATCHER_VOICE_STATE_READY,
    GPTNIX_WATCHER_VOICE_STATE_CLOSED,
    GPTNIX_WATCHER_VOICE_STATE_ERROR,
} app_gptnix_watcher_voice_state_t;

typedef enum {
    GPTNIX_WATCHER_VOICE_RESULT_OK = 0,
    GPTNIX_WATCHER_VOICE_RESULT_DISABLED,
    GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT,
    GPTNIX_WATCHER_VOICE_RESULT_INVALID_SESSION_DTO,
    GPTNIX_WATCHER_VOICE_RESULT_UNSUPPORTED_CONTRACT,
    GPTNIX_WATCHER_VOICE_RESULT_NO_MEMORY,
    GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED,
    GPTNIX_WATCHER_VOICE_RESULT_WS_START_FAILED,
    GPTNIX_WATCHER_VOICE_RESULT_WS_SEND_FAILED,
    GPTNIX_WATCHER_VOICE_RESULT_PROTOCOL_ERROR,
    GPTNIX_WATCHER_VOICE_RESULT_REMOTE_CLOSED,
} app_gptnix_watcher_voice_result_t;

esp_err_t app_gptnix_watcher_voice_init(void);
esp_err_t app_gptnix_watcher_voice_deinit(void);

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_prepare_session(
    const char *session_json,
    size_t session_len);

app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_connect(void);
app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_disconnect(void);

app_gptnix_watcher_voice_state_t app_gptnix_watcher_voice_get_state(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_GPTNIX_WATCHER_VOICE_H */
