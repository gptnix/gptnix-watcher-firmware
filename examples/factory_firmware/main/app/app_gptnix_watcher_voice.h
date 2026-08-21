/**
 * GPTNiX Watcher realtime-voice WSS transport/session foundation.
 *
 * The ONE canonical firmware owner for the GPTNiX Gemini Live WebSocket
 * transport/session lifecycle. Consumes a backend-provisioned session DTO
 * (see docs/GPTNIX_WATCHER_VOICE_TRANSPORT_CONTRACT_V1.md) and drives the
 * connect -> setup -> setupComplete handshake, plus (M3C,
 * plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md) sending realtimeInput audio and
 * recognizing serverContent audio replies.
 *
 * M3C scope note: this module still never touches the microphone/speaker
 * APIs directly (a fitness-enforced boundary) -- outgoing audio is supplied
 * by the caller (app_gptnix_watcher_voice_send_audio), and incoming audio is
 * delivered via a registered callback (app_gptnix_watcher_voice_audio_cb_t)
 * rather than this module calling the audio player itself. No Firebase/
 * pairing/HTTP bootstrap, no device flash -- those remain out of scope.
 */
#ifndef APP_GPTNIX_WATCHER_VOICE_H
#define APP_GPTNIX_WATCHER_VOICE_H

#include <stdbool.h>
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

/**
 * M3C runtime audio bridge (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md). Sends one chunk of already-captured
 * microphone PCM (16kHz/16-bit/mono, matching the BSP's fixed capture rate and Gemini's expected
 * realtimeInput format exactly -- no resampling needed on this side) as a Gemini `realtimeInput` message.
 * Requires state == READY; returns GPTNIX_WATCHER_VOICE_RESULT_INVALID_ARGUMENT otherwise. Never logs the
 * audio content.
 */
app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_send_audio(const uint8_t *pcm_data, size_t pcm_len);

/**
 * Invoked once per decoded audio chunk from Gemini's spoken response (pcm_data/pcm_len, 24kHz/16-bit/mono
 * raw PCM, turn_complete=false), and once more with pcm_data=NULL/pcm_len=0/turn_complete=true when
 * Gemini's turn ends. This module deliberately never touches the speaker/audio-player APIs itself (a
 * pre-existing, fitness-enforced separation-of-concerns boundary) -- the callback lets an external module
 * (see app_gptnix_watcher_voice_runtime.c) own that. Called from the WS event handler's context.
 */
typedef void (*app_gptnix_watcher_voice_audio_cb_t)(
    const uint8_t *pcm_data, size_t pcm_len, bool turn_complete, void *user_data);

void app_gptnix_watcher_voice_set_audio_callback(app_gptnix_watcher_voice_audio_cb_t cb, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* APP_GPTNIX_WATCHER_VOICE_H */
