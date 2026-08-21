/**
 * GPTNiX Watcher M3C runtime audio bridge entry point.
 *
 * See app_gptnix_watcher_voice_runtime.h and plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md.
 *
 * Owns BOTH sides of the boundary app_gptnix_watcher_voice.c deliberately never crosses itself: the mic-
 * feeding task (pulls from the recorder, pushes into the WS session) and the audio-received callback
 * (decodes Gemini's spoken response, forwards to the speaker) -- keeping the transport/session module
 * hardware-agnostic while this module owns the actual microphone/speaker API calls.
 */
#include "app_gptnix_watcher_voice_runtime.h"
#include "sdkconfig.h"

#if CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME

#include <stddef.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "app_gptnix_watcher_voice.h"
#include "app_audio_recorder.h"
#include "app_audio_player.h"

static const char *TAG = "V2_WATCHER_VOICE_RUNTIME";

#define GW_AUDIO_BRIDGE_TASK_STACK_BYTES  (8192)
#define GW_AUDIO_BRIDGE_TASK_PRIO         (10)
#define GW_AUDIO_BRIDGE_RECV_TIMEOUT_MS   (500)
#define GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS   (2000)
#define GW_AUDIO_OUT_SAMPLE_RATE          (24000)
#define GW_AUDIO_OUT_BITS_PER_SAMPLE      (16)
#define GW_AUDIO_OUT_CHANNELS             (1)

/* True once app_audio_player_stream_init()/stream_start() have been called for the CURRENT Gemini
 * response turn -- the synthesized WAV header is only prepended to the first chunk of a stream (matches
 * app_audio_player's own WAV-detection contract, see app_audio_player.c's __is_wav()). Reset on
 * turnComplete. Single-writer (this callback runs on the WS event handler's own task context, same as
 * every other voice.c event -- no locking needed, matching that module's existing threading model). */
static bool s_player_stream_active = false;

/* M3C: registered as app_gptnix_watcher_voice.c's audio callback -- owns the ONLY app_audio_player_*
 * call sites reachable from a Gemini WS event, keeping voice.c itself hardware-agnostic (a pre-existing,
 * fitness-enforced separation-of-concerns boundary). Never logs audio content. */
static void s_on_audio_received(const uint8_t *pcm_data, size_t pcm_len, bool turn_complete, void *user_data)
{
    (void)user_data;

    if (turn_complete) {
        if (s_player_stream_active) {
            app_audio_player_stream_finish();
            s_player_stream_active = false;
        }
        return;
    }
    if (pcm_data == NULL || pcm_len == 0) {
        return;
    }

    if (!s_player_stream_active) {
        app_audio_player_stream_init(0);
        app_audio_player_stream_start();
        s_player_stream_active = true;

        audio_wav_header_t h;
        memcpy(h.ChunkID, "RIFF", 4);
        h.ChunkSize = (int32_t)(36 + pcm_len);
        memcpy(h.Format, "WAVE", 4);
        memcpy(h.Subchunk1ID, "fmt ", 4);
        h.Subchunk1Size = 16;
        h.AudioFormat = 1;
        h.NumChannels = GW_AUDIO_OUT_CHANNELS;
        h.SampleRate = GW_AUDIO_OUT_SAMPLE_RATE;
        h.ByteRate = GW_AUDIO_OUT_SAMPLE_RATE * GW_AUDIO_OUT_CHANNELS * GW_AUDIO_OUT_BITS_PER_SAMPLE / 8;
        h.BlockAlign = GW_AUDIO_OUT_CHANNELS * GW_AUDIO_OUT_BITS_PER_SAMPLE / 8;
        h.BitsPerSample = GW_AUDIO_OUT_BITS_PER_SAMPLE;
        memcpy(h.Subchunk2ID, "data", 4);
        h.Subchunk2Size = (int32_t)pcm_len;

        uint8_t *framed = (uint8_t *)malloc(sizeof(h) + pcm_len);
        if (framed == NULL) {
            return;
        }
        memcpy(framed, &h, sizeof(h));
        memcpy(framed + sizeof(h), pcm_data, pcm_len);
        app_audio_player_stream_send(framed, sizeof(h) + pcm_len, pdMS_TO_TICKS(GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS));
        free(framed);
        return;
    }

    app_audio_player_stream_send((uint8_t *)pcm_data, pcm_len, pdMS_TO_TICKS(GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS));
}

/* Never logs audio content -- only structural, non-secret task lifecycle markers. */
static void s_audio_bridge_task(void *arg)
{
    (void)arg;
    esp_err_t start_err = app_audio_recorder_stream_start();
    if (start_err != ESP_OK) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] recorder_start_failed err=%d", (int)start_err);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] task_started");

    for (;;) {
        app_gptnix_watcher_voice_state_t state = app_gptnix_watcher_voice_get_state();
        if (state != GPTNIX_WATCHER_VOICE_STATE_READY) {
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] session_ended state=%d", (int)state);
            break;
        }

        size_t recv_len = 0;
        uint8_t *chunk = app_audio_recorder_stream_recv(&recv_len,
            pdMS_TO_TICKS(GW_AUDIO_BRIDGE_RECV_TIMEOUT_MS));
        if (chunk == NULL) {
            continue; /* no audio arrived within the wait window -- loop and re-check state */
        }
        if (recv_len > 0) {
            (void)app_gptnix_watcher_voice_send_audio(chunk, recv_len);
        }
        app_audio_recorder_stream_free(chunk);
    }

    app_audio_recorder_stream_stop();
    vTaskDelete(NULL);
}

void app_gptnix_watcher_voice_runtime_start(void)
{
    s_player_stream_active = false;
    app_gptnix_watcher_voice_set_audio_callback(s_on_audio_received, NULL);

    TaskHandle_t handle = NULL;
    BaseType_t created = xTaskCreate(s_audio_bridge_task, "gw_audio_bridge",
        GW_AUDIO_BRIDGE_TASK_STACK_BYTES, NULL, GW_AUDIO_BRIDGE_TASK_PRIO, &handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] task_create_failed");
    }
}

#else

void app_gptnix_watcher_voice_runtime_start(void)
{
    /* CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME disabled: no-op. */
}

#endif /* CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME */
