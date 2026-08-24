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
#include "freertos/ringbuf.h"
#include "freertos/queue.h"

#include "app_gptnix_watcher_voice.h"
#include "app_audio_recorder.h"
#include "app_audio_player.h"
#include "esp_heap_caps.h"
#include "esp_event.h"
#include "event_loops.h"
#include "data_defs.h"
#include <stdio.h>
#include "util.h"

static const char *TAG = "V2_WATCHER_VOICE_RUNTIME";

#define GW_AUDIO_BRIDGE_TASK_STACK_BYTES  (8192)
/* M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test showed continuous
 * "xRingbufferSend failed" errors from app_audio_recorder.c (AUDIO_RECORDER_TASK_PRIO=13, see
 * app_audio_recorder.h) -- its capture producer was finding the ring buffer still full because this
 * consumer task, at a LOWER priority (10), wasn't getting scheduled promptly enough while blocked inside
 * synchronous WS sends. Raised above the recorder's own priority so the consumer always preempts equal-
 * or-lower-priority work as soon as it's runnable. Gemini received mostly-empty/garbled audio as a
 * direct result (server replies were content-less turn-signal frames, no actual speech).
 */
#define GW_AUDIO_BRIDGE_TASK_PRIO         (14)
#define GW_AUDIO_BRIDGE_RECV_TIMEOUT_MS   (500)
/* M3C fix: fewer, larger synchronous WS sends per captured buffer reduces total time this task spends
 * blocked (each send does base64 encode + cJSON build + a blocking TLS write) between ring-buffer drains,
 * which was the other half of the overflow above. 4000 hit a transport_poll_write / esp_transport_write()
 * ==0 failure that killed the whole session (matching the known large-send reliability issue); 2000
 * caused CONTINUOUS ring-buffer overflow instead (8 sequential blocking sends per 16000-byte captured
 * buffer was too much fixed per-call overhead to drain within one ~500ms capture cycle, dropping nearly
 * all audio). 3000 is the live-tested middle ground: 6 calls/cycle instead of 8, and 25% under the size
 * that tripped the transport failure. */
#define GW_AUDIO_SEND_PIECE_MAX_BYTES      (3000)
#define GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS   (2000)
// Shared-codec fix (2026-08-23 follow-up, per Gemini second-opinion review of the same root-cause
// writeup): 16000 instead of Gemini's native 24000 -- Gemini's raw output is resampled down to 16kHz
// (matching the mic's fixed capture rate) in s_resample_24k_to_16k() below, BEFORE it ever reaches the
// player. Root cause this avoids entirely: app_audio_player.c resets its own tracked sample_rate on every
// stream_init() call, so every single Gemini reply (always declaring 24000 in its WAV header) re-triggered
// bsp_codec_set_fs() (vendor BSP, sensecap-watcher.c) -- which closes AND reopens BOTH the play AND record
// esp_codec_dev handles together (confirmed by reading esp_codec_dev_open()'s source: it reconfigures the
// data_if shared by both directions, consistent with RX/TX sharing one I2S clock on this hardware). That
// left the recorder task's underlying device desynced after the FIRST reply, silently producing nothing
// on later mic captures. A first attempt to fix this by explicitly restarting the recorder stream after
// each reply caused a WORSE regression (a full task-watchdog crash, likely priority starvation or a
// mutex ordering issue against the player's own codec_mutex use) and was reverted. Normalizing all audio
// to one fixed 16kHz before it ever reaches the driver layer sidesteps the shared-codec state machine
// entirely instead of fighting it.
#define GW_AUDIO_OUT_SAMPLE_RATE          (16000)
#define GW_AUDIO_OUT_BITS_PER_SAMPLE      (16)
#define GW_AUDIO_OUT_CHANNELS             (1)
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the operator directly heard audible
// stutter/jitter in Gemini's spoken reply even with zero send-failure/overflow warnings logged anywhere
// -- per Gemini Live's own best-practices doc (ai.google.dev/gemini-api/docs/live-api/best-practices:
// "wait for a minimum buffer size (~170ms) before beginning playback ... helps prevent stuttering") the
// old code started playback on the very FIRST chunk with no headroom at all, so any natural gap between
// receiving/decoding successive WS chunks (network jitter, JSON/base64 decode time) could starve the
// player's own ring buffer even though nothing "failed". Accumulates roughly this much audio before
// starting playback, giving the player headroom to absorb delivery jitter without an audible glitch.
#define GW_PLAYER_PREBUFFER_THRESHOLD_BYTES (32000) /* ~1s of 16kHz/16-bit/mono (post-resample) */
#define GW_PLAYER_PREBUFFER_MAX_BYTES       (64000) /* ~2s hard cap -- flush early rather than drop data */

// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the pre-buffer above only smooths the START
// of a reply -- the operator confirmed it helped but did NOT eliminate stuttering, since every chunk
// AFTER the first was still fed to app_audio_player_stream_send() directly from this WS-event-driven
// callback, with no headroom against ongoing delivery jitter (network irregularity, JSON/base64 decode
// time). Applying the SAME decoupling pattern already proven on the mic-upload side (drain into a local
// queue, feed from a dedicated task) here too: the callback only enqueues (fast, never blocks on the
// player), a separate feeder task does the actual (blocking) app_audio_player_stream_send() calls, so
// WS delivery jitter for the ENTIRE reply is absorbed by the queue instead of only the first chunk.
typedef struct {
    uint8_t *data;        /* PSRAM-allocated copy, freed by the feeder task after sending; NULL means
                              this item is a turn_complete signal, not audio. */
    size_t len;
    bool turn_complete;
} gw_player_feed_item_t;

#define GW_PLAYER_FEED_QUEUE_DEPTH        (32)   /* items, not bytes -- bounded mainly by PSRAM headroom */
#define GW_PLAYER_FEED_TASK_STACK_BYTES   (8192)
#define GW_PLAYER_FEED_TASK_PRIO          (12)   /* just under AUDIO_PLAYER_TASK_PRIO(13, app_audio_player.h)
                                                     so it never starves the player's own task, but still
                                                     preempts the lower-priority mic send task (10) */
static QueueHandle_t s_player_feed_queue = NULL;

// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): live testing (user actually speaking, longer
// utterances) showed response latency growing from ~10s to ~50s -- traced to this task doing BOTH the
// recorder-ring-buffer drain AND the blocking WS network send in one loop, so any network slowness
// (TLS write stalls, congestion) directly stalled draining too, compounding backlog the longer the user
// talked. Per Gemini Live's own best-practices doc (ai.google.dev/gemini-api/docs/live-api/best-practices:
// "don't buffer input audio significantly... send small chunks (20-100ms) to minimize latency") and the
// standard ESP32 pattern for this exact problem (drain into a local ring buffer without blocking, send
// from a separate task), splits into two tasks below: s_audio_capture_task ONLY drains the recorder (never
// blocks on network), s_audio_send_task ONLY does the WS sends, decoupled via GW_AUDIO_LOCAL_RB.
#define GW_AUDIO_SEND_TASK_STACK_BYTES     (8192)
#define GW_AUDIO_SEND_TASK_PRIO            (10)
// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live timing measurement showed individual
// sends are usually fast (~90-200ms for a 3000-byte piece) but periodically spike to 0.4-1.6s (network/
// TLS contention), and no real Gemini reply arrived within 100 continuous seconds of a live test despite
// the session staying alive and sends continuing -- while local_rb_overflow kept firing. Working theory:
// even occasional 16000-byte drops fragment/garble the utterance from Gemini's side, so its own speech
// understanding and end-of-turn detection may never resolve cleanly, rather than just being "slow".
// Enlarged from 8s to ~30s so a realistic utterance is delivered to Gemini complete and ungapped even
// under sustained network slowness -- trading (already-present, unavoidable at today's throughput)
// backlog delay for delivery correctness, on the theory that a correct-but-delayed transcript is more
// likely to get ANY response than a fast-but-gapped one that Gemini can never resolve into a turn.
#define GW_AUDIO_LOCAL_RB_SIZE_BYTES       (960000) /* ~30s of 16kHz/16-bit/mono audio */
#define GW_AUDIO_LOCAL_RB_ITEM_MAX_BYTES   (16000)  /* matches AUDIO_RECORDER_RINGBUF_CHUNK_SIZE */
#define GW_AUDIO_LOCAL_RB_PUSH_TIMEOUT_MS  (100)    /* short on purpose: a full local buffer means the
                                                       send task has been stalled for ~8s already -- drop
                                                       this piece rather than block capture and cascade
                                                       into the SAME recorder-overflow bug being fixed. */

static RingbufHandle_t s_mic_local_rb = NULL;
static uint8_t *s_mic_local_rb_storage = NULL;
static StaticRingbuffer_t s_mic_local_rb_struct;

/* True once app_audio_player_stream_init()/stream_start() have been called for the CURRENT Gemini
 * response turn -- the synthesized WAV header is only prepended to the first chunk of a stream (matches
 * app_audio_player's own WAV-detection contract, see app_audio_player.c's __is_wav()). Reset on
 * turnComplete. Single-writer (this callback runs on the WS event handler's own task context, same as
 * every other voice.c event -- no locking needed, matching that module's existing threading model). */
// Cross-task visibility fix (2026-08-23 follow-up): a live physical test proved the mute gate was NOT
// reliably taking effect -- audio_send lines kept firing continuously for 9+ seconds after
// s_prebuffering should have gone true (confirmed via server_content parts=1 arriving well before the
// gate engaged). Root cause: this flag is written by the WS event handler task and read in a tight loop
// by the separate capture/send tasks, but was never declared volatile -- the compiler is free to cache
// a non-volatile read across loop iterations (and, on this dual-core target, tasks may run on a
// different core than the writer), so the reader task could keep observing a stale cached value
// indefinitely instead of re-reading memory. Same fix applied to s_prebuffering below.
static volatile bool s_player_stream_active = false;

// Knob-trigger follow-up (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up, 2026-08-23): default OFF
// (push-to-talk, not always-listening) -- addresses the operator's stated privacy concern about the
// device "hearing everything" continuously. Only gates the REAL capture task below; the synthetic-test-
// audio capture task (CONFIG_GPTNIX_WATCHER_VOICE_SYNTHETIC_TEST_AUDIO) never checks this, so autonomous/
// CI testing is unaffected. Plain bool, single extra reader (the capture task loop) -- same tolerated-
// cross-task-read pattern already used for s_player_stream_active in this file. Driven exclusively by
// CTRL_EVENT_GW_LISTEN_START/STOP (see s_ctrl_event_handler below), posted by main.c's knob long-press/
// long-release trampolines -- main.c itself never references this module directly, preserving the
// pre-existing "main.c never calls the M2 realtime-voice API" boundary.
static volatile bool s_listening_active = false;

// M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): see GW_PLAYER_PREBUFFER_* comment above --
// accumulates the start of a reply here before actually starting playback, instead of starting on the
// very first (possibly tiny) chunk.
static uint8_t *s_prebuffer = NULL;
static size_t s_prebuffer_len = 0;
static volatile bool s_prebuffering = false;

/* Starts the player stream with pcm_data/pcm_len as the FIRST chunk (WAV-header-framed, per
 * app_audio_player.c's __is_wav() contract). Shared by both the pre-buffer-threshold-reached path and
 * the turn_complete-before-threshold flush path below. */
static void s_start_player_stream_with(const uint8_t *pcm_data, size_t pcm_len)
{
    esp_err_t init_err = app_audio_player_stream_init(0);
    esp_err_t start_err = app_audio_player_stream_start();
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

    // M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the user reported the first
    // physical audio playback sounded like noise, not clear speech -- logging only non-secret
    // structural facts (error codes, struct size, byte counts) to narrow down whether the cause is
    // the sample-rate reconfiguration failing, a header-size mismatch, or something else.
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] first_chunk: init_err=%d start_err=%d hdr_sizeof=%d pcm_len=%d",
        (int)init_err, (int)start_err, (int)sizeof(h), (int)pcm_len);

    uint8_t *framed = (uint8_t *)heap_caps_malloc(sizeof(h) + pcm_len, MALLOC_CAP_SPIRAM);
    if (framed == NULL) {
        return;
    }
    memcpy(framed, &h, sizeof(h));
    memcpy(framed + sizeof(h), pcm_data, pcm_len);
    esp_err_t send_err = app_audio_player_stream_send(framed, sizeof(h) + pcm_len, pdMS_TO_TICKS(GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS));
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] first_chunk: send_err=%d", (int)send_err);
    free(framed);
    // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): live testing traced send_err=-1 on
    // EVERY first chunk to app_audio_player.c's own AUDIO_TYPE_UNKNOWN/WAV-detection branch (a
    // protected, fitness-frozen file this codebase never modifies -- see check "45. app_audio_player.c
    // untouched" -- so the caller must adapt instead): its ring-send condition there is inverted
    // (`if (xRingbufferSend(...) == pdTRUE) return ESP_FAIL;`), unlike the correct `!= pdTRUE` used
    // for every later chunk a few lines below it in the same function. So on the FIRST chunk only,
    // ESP_FAIL from this call means the audio WAS successfully queued -- treating it as a real
    // failure (and resetting s_player_stream_active) was itself corrupting every stream by
    // re-sending a bogus second WAV header for what the player already saw as chunk 2 of 1.
}

// Shared-codec fix (2026-08-23 follow-up): streaming linear-interpolation resampler, 24000Hz (Gemini's
// native output) -> 16000Hz (the mic's fixed capture rate, and now the player's only-ever rate -- see the
// GW_AUDIO_OUT_SAMPLE_RATE comment above for why). Phase-continuous across chunk boundaries via
// s_resample_prev/s_resample_pos, since Gemini's audio arrives as many small chunks, not one buffer --
// without carrying state across calls, every chunk boundary would produce an audible click/warp. Reset on
// every new turn (interrupted or turn_complete) so one turn's trailing phase never bleeds into the next.
// Linear interpolation (not a full FIR/polyphase filter) is adequate for voice intelligibility at this
// milestone and is simple enough to reason about correctness for under time pressure -- a definite,
// bounded-latency, allocation-free-per-sample transform, not a research-grade resampler.
static int16_t s_resample_prev = 0;
static float s_resample_pos = 1.0f;

static size_t s_resample_24k_to_16k(const int16_t *in, size_t in_samples, int16_t *out, size_t out_cap)
{
    const float step = 24000.0f / 16000.0f; /* 1.5 input samples advance per output sample */
    size_t out_count = 0;
    while (out_count < out_cap) {
        int i0 = (int)s_resample_pos;
        if ((size_t)(i0 + 1) > in_samples) {
            break;
        }
        float t = s_resample_pos - (float)i0;
        int16_t v0 = (i0 == 0) ? s_resample_prev : in[i0 - 1];
        int16_t v1 = in[i0];
        out[out_count++] = (int16_t)((float)v0 + t * (float)(v1 - v0));
        s_resample_pos += step;
    }
    if (in_samples > 0) {
        s_resample_prev = in[in_samples - 1];
    }
    s_resample_pos -= (float)in_samples;
    return out_count;
}

/* M3C: registered as app_gptnix_watcher_voice.c's audio callback -- owns the ONLY app_audio_player_*
 * call sites reachable from a Gemini WS event, keeping voice.c itself hardware-agnostic (a pre-existing,
 * fitness-enforced separation-of-concerns boundary). Never logs audio content. */
static void s_on_audio_received(const uint8_t *pcm_data, size_t pcm_len, bool turn_complete, bool interrupted,
                                 void *user_data)
{
    (void)user_data;

    // M3C fix (web research follow-up, plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): community-validated
    // pattern for serverContent.interrupted (Google AI Developers Forum "Hard-Won Patterns" thread;
    // eastondev.com Gemini Live tutorial; ai.google.dev/gemini-api/docs/live-api/best-practices) is to
    // stop playback and discard buffered/queued audio for the aborted turn immediately -- previously we
    // only logged this field, so an aborted turn's already-prebuffered/queued audio still played out in
    // full once the following turnComplete arrived. Complements (does not replace) the mute-timing fix
    // above, which reduces how often interrupted=true fires falsely in the first place; this handles it
    // correctly on the rare/legitimate occasions it still does.
    if (interrupted) {
        bool had_prebuffer = s_prebuffering && s_prebuffer_len > 0;
        s_prebuffering = false;
        s_prebuffer_len = 0;
        s_resample_prev = 0;
        s_resample_pos = 1.0f;

        int drained = 0;
        gw_player_feed_item_t stale;
        while (xQueueReceive(s_player_feed_queue, &stale, 0) == pdTRUE) {
            if (stale.data != NULL) {
                free(stale.data);
            }
            drained++;
        }

        if (s_player_stream_active) {
            // Enqueued (not called directly) so app_audio_player_stream_finish() only ever runs on the
            // feeder task's own context, matching every other lifecycle transition in this file.
            gw_player_feed_item_t finish_item = { .data = NULL, .len = 0, .turn_complete = true };
            (void)xQueueSend(s_player_feed_queue, &finish_item, pdMS_TO_TICKS(2000));
        }

        ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] interrupted_flush had_prebuffer=%d drained=%d stream_active=%d",
            (int)had_prebuffer, drained, (int)s_player_stream_active);
        return;
    }

    if (turn_complete) {
        if (s_prebuffering && s_prebuffer_len > 0) {
            // Reply ended before the pre-buffer threshold was reached (a short reply) -- flush whatever
            // was accumulated as the one and only chunk rather than discarding it.
            s_start_player_stream_with(s_prebuffer, s_prebuffer_len);
        }
        s_prebuffering = false;
        s_prebuffer_len = 0;
        s_resample_prev = 0;
        s_resample_pos = 1.0f;
        // Enqueued (not called directly) so it's processed by the feeder task AFTER any audio items
        // already queued ahead of it -- calling stream_finish() synchronously here could race ahead of
        // still-unsent queued audio from the same turn.
        gw_player_feed_item_t item = { .data = NULL, .len = 0, .turn_complete = true };
        (void)xQueueSend(s_player_feed_queue, &item, pdMS_TO_TICKS(2000));
        return;
    }
    // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test showed Gemini
    // occasionally sending a near-empty first audio part (observed: 2 raw PCM bytes) as the start of a
    // turn -- too small to be meaningful audio, and its WAV-header-carrying send failed, which (before
    // this fix) permanently marked the stream "active" without the player ever having actually received
    // a valid header, silently breaking every subsequent real chunk in that turn. Skips chunks too small
    // to carry a real sample pair (stereo/mono 16-bit) instead of starting a stream on them.
    if (pcm_data == NULL || pcm_len < 4) {
        return;
    }

    size_t in_samples = pcm_len / 2;
    size_t out_cap = (in_samples * 2) / 3 + 4;
    int16_t *resampled = (int16_t *)heap_caps_malloc(out_cap * sizeof(int16_t), MALLOC_CAP_SPIRAM);
    if (resampled == NULL) {
        ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] resample_alloc_failed pcm_len=%d", (int)pcm_len);
        return;
    }
    size_t out_samples = s_resample_24k_to_16k((const int16_t *)pcm_data, in_samples, resampled, out_cap);
    pcm_data = (const uint8_t *)resampled;
    pcm_len = out_samples * 2;
    if (pcm_len < 4) {
        free(resampled);
        return;
    }

    if (!s_player_stream_active) {
        if (!s_prebuffering) {
            s_prebuffering = true;
            s_prebuffer_len = 0;
            if (s_prebuffer == NULL) {
                s_prebuffer = (uint8_t *)heap_caps_malloc(GW_PLAYER_PREBUFFER_MAX_BYTES, MALLOC_CAP_SPIRAM);
            }
        }
        if (s_prebuffer != NULL) {
            size_t space_left = GW_PLAYER_PREBUFFER_MAX_BYTES - s_prebuffer_len;
            size_t copy_len = (pcm_len < space_left) ? pcm_len : space_left;
            memcpy(s_prebuffer + s_prebuffer_len, pcm_data, copy_len);
            s_prebuffer_len += copy_len;
        }
        if (s_prebuffer == NULL || s_prebuffer_len >= GW_PLAYER_PREBUFFER_THRESHOLD_BYTES) {
            s_prebuffering = false;
            if (s_prebuffer != NULL && s_prebuffer_len > 0) {
                s_start_player_stream_with(s_prebuffer, s_prebuffer_len);
            } else {
                // Allocation failed -- fall back to the old immediate-start behavior rather than losing
                // this chunk entirely.
                s_start_player_stream_with(pcm_data, pcm_len);
            }
            s_prebuffer_len = 0;
        }
        free(resampled);
        return;
    }

    uint8_t *copy = (uint8_t *)heap_caps_malloc(pcm_len, MALLOC_CAP_SPIRAM);
    if (copy == NULL) {
        ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] feed_queue_alloc_failed pcm_len=%d", (int)pcm_len);
        free(resampled);
        return;
    }
    memcpy(copy, pcm_data, pcm_len);
    gw_player_feed_item_t item = { .data = copy, .len = pcm_len, .turn_complete = false };
    if (xQueueSend(s_player_feed_queue, &item, pdMS_TO_TICKS(500)) != pdTRUE) {
        // Queue genuinely full (feeder stalled for a while) -- drop this piece rather than blocking the
        // WS event handler's own task indefinitely, which would stall RX processing for the whole session.
        ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] feed_queue_full dropped_len=%d", (int)pcm_len);
        free(copy);
    }
    free(resampled);
}

/* Drains s_player_feed_queue and does the actual (blocking) app_audio_player_stream_send() calls --
 * fully decoupled from the WS event handler's own task, so delivery jitter for the WHOLE reply (not just
 * the pre-buffered first chunk) is absorbed here instead of causing an audible playback gap. */
static void s_player_feed_task(void *arg)
{
    (void)arg;
    for (;;) {
        gw_player_feed_item_t item;
        if (xQueueReceive(s_player_feed_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (item.turn_complete) {
            if (s_player_stream_active) {
                app_audio_player_stream_finish();
                s_player_stream_active = false;
            }
            continue;
        }
        esp_err_t send_err = app_audio_player_stream_send(item.data, item.len, pdMS_TO_TICKS(GW_AUDIO_BRIDGE_SEND_TIMEOUT_MS));
        if (send_err != ESP_OK) {
            ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] chunk_send_failed err=%d pcm_len=%d", (int)send_err, (int)item.len);
        }
        free(item.data);
    }
}

#if CONFIG_GPTNIX_WATCHER_VOICE_SYNTHETIC_TEST_AUDIO
#define GW_SYNTHETIC_TEST_AUDIO_PATH   "/spiffs/gptnix_synth_test.pcm"
#define GW_SYNTHETIC_CHUNK_BYTES       (16000) /* matches AUDIO_RECORDER_RINGBUF_CHUNK_SIZE pacing */
#define GW_SYNTHETIC_CHUNK_PERIOD_MS   (500)    /* 16000B @16kHz/16-bit/mono == real capture cadence */

/* M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): feeds a canned SPIFFS clip into the
 * SAME downstream pipeline a live microphone capture would, paced to match real-time cadence, so
 * round-trip latency/quality testing works without a human physically present to speak. Never calls any
 * app_audio_recorder_* API in this mode -- the speaker/playback path is completely unaffected. */
static void s_audio_capture_task(void *arg)
{
    (void)arg;
    FILE *f = fopen(GW_SYNTHETIC_TEST_AUDIO_PATH, "rb");
    if (f == NULL) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] synthetic_open_failed path=%s", GW_SYNTHETIC_TEST_AUDIO_PATH);
        vTaskDelete(NULL);
        return;
    }
    uint8_t *chunk_buf = (uint8_t *)heap_caps_malloc(GW_SYNTHETIC_CHUNK_BYTES, MALLOC_CAP_SPIRAM);
    if (chunk_buf == NULL) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] synthetic_alloc_failed");
        fclose(f);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] capture_task_started mode=synthetic");

    for (;;) {
        app_gptnix_watcher_voice_state_t state = app_gptnix_watcher_voice_get_state();
        if (state != GPTNIX_WATCHER_VOICE_STATE_READY) {
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] capture_task_ended state=%d", (int)state);
            break;
        }

        size_t recv_len = fread(chunk_buf, 1, GW_SYNTHETIC_CHUNK_BYTES, f);
        if (recv_len == 0) {
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] synthetic_playback_complete");
            break;
        }
        if (s_player_stream_active || s_prebuffering) {
            vTaskDelay(pdMS_TO_TICKS(GW_SYNTHETIC_CHUNK_PERIOD_MS));
            continue;
        }
        if (xRingbufferSend(s_mic_local_rb, chunk_buf, recv_len, pdMS_TO_TICKS(GW_AUDIO_LOCAL_RB_PUSH_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] local_rb_overflow dropped_len=%d", (int)recv_len);
        }
        vTaskDelay(pdMS_TO_TICKS(GW_SYNTHETIC_CHUNK_PERIOD_MS));
    }

    fclose(f);
    free(chunk_buf);

    // M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the synthetic PCM clip above
    // already exercises and proves the full mic-upload pipeline (timing, zero-drop delivery), but the
    // espeak-ng-synthesized voice has not reliably elicited a real Gemini reply across repeated live
    // tests -- a synthetic-speech-intelligibility limitation, not a pipeline defect. Sending one
    // deterministic text turn as a fallback guarantees a real reply for testing the REST of the pipeline
    // (playback, the playback-interruption fix, end-to-end timing) without depending on that.
    (void)app_gptnix_watcher_voice_send_text_turn(
        "Bok! Reci mi ukratko, jednom recenicom, kako si danas.");

    vTaskDelete(NULL);
}
#else
/* Drains the recorder's OWN ring buffer ONLY -- never touches the network, so it can always keep pace
 * with capture regardless of WS/TLS send speed. Forwards into the local send-side ring buffer for
 * s_audio_send_task to pick up independently. Never logs audio content. */
static void s_audio_capture_task(void *arg)
{
    (void)arg;
    esp_err_t start_err = app_audio_recorder_stream_start();
    if (start_err != ESP_OK) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] recorder_start_failed err=%d", (int)start_err);
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] capture_task_started");

    // Diagnostic follow-up (2026-08-24, diag/m3c-recorder-stall-rootcause, Phase A): replaces the prior
    // per-chunk-only `gate_check` line (which could only ever fire AFTER a non-NULL chunk, and therefore
    // could not distinguish "stream_recv() keeps returning NULL" from "this task itself stopped
    // progressing"). These counters are local to this task's own stack frame (no global owner needed,
    // this task is the sole reader/writer) and are updated on EVERY loop iteration, NULL or not, so a
    // rate-limited heartbeat below can prove liveness independent of whether any audio was received.
    uint32_t loop_count = 0;
    uint32_t chunk_count = 0;
    uint32_t byte_count = 0;
    uint32_t null_count = 0;
    uint32_t null_streak = 0;
    TickType_t last_diag_tick = xTaskGetTickCount();

    for (;;) {
        app_gptnix_watcher_voice_state_t state = app_gptnix_watcher_voice_get_state();
        if (state != GPTNIX_WATCHER_VOICE_STATE_READY) {
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] capture_task_ended state=%d", (int)state);
            break;
        }

        loop_count++;
        TickType_t recv_start_tick = xTaskGetTickCount();
        size_t recv_len = 0;
        uint8_t *chunk = app_audio_recorder_stream_recv(&recv_len,
            pdMS_TO_TICKS(GW_AUDIO_BRIDGE_RECV_TIMEOUT_MS));
        TickType_t recv_elapsed_ticks = xTaskGetTickCount() - recv_start_tick;

        if (chunk == NULL) {
            null_count++;
            null_streak++;
        } else {
            chunk_count++;
            byte_count += (uint32_t)recv_len;
            null_streak = 0;
        }

        TickType_t now_tick = xTaskGetTickCount();
        if ((now_tick - last_diag_tick) >= pdMS_TO_TICKS(2000)) {
            last_diag_tick = now_tick;
            ESP_LOGI(TAG,
                "[V2_WATCHER_VOICE_RUNTIME] capture_diag: loops=%lu chunks=%lu bytes=%lu nulls=%lu "
                "null_streak=%lu recv_ms=%lu rec_status=%d listen=%d player=%d prebuffer=%d stack_hwm=%lu",
                (unsigned long)loop_count, (unsigned long)chunk_count, (unsigned long)byte_count,
                (unsigned long)null_count, (unsigned long)null_streak,
                (unsigned long)(recv_elapsed_ticks * portTICK_PERIOD_MS),
                app_audio_recorder_status_get(),
                (int)s_listening_active, (int)s_player_stream_active, (int)s_prebuffering,
                (unsigned long)uxTaskGetStackHighWaterMark(NULL));
        }

        if (chunk == NULL) {
            continue; /* no audio arrived within the wait window -- loop and re-check state */
        }
        // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test showed Gemini's
        // spoken response being cut off/interrupted -- the mic keeps sending continuously even while the
        // device's OWN speaker is actively playing Gemini's response, which the mic picks back up
        // (acoustic feedback) and Gemini interprets as the user barging in. Mutes the mic's OUTGOING
        // stream (still drains/frees the recorder's ring buffer to avoid backlog) whenever a player
        // stream is active. Not full echo cancellation -- a pragmatic half-duplex approach for this
        // milestone; real barge-in support is a documented non-goal (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md).
        // M3C fix (follow-up #2): confirmed live via a new `interrupted` diagnostic that Gemini really
        // was sending its own barge-in signal. Root cause: `s_player_stream_active` only became true once
        // the pre-buffer threshold was reached (~1s after Gemini's reply started arriving), so the mic
        // kept sending real audio for that entire window even though Gemini had ALREADY started
        // responding -- exactly what a HIGH-sensitivity VAD (tuned for latency, see GeminiLiveTokenBroker.
        // js) would interpret as the user talking over it. Also checking s_prebuffering mutes the instant
        // the reply starts arriving, not just once hardware playback actually begins.
        if (!s_listening_active || s_player_stream_active || s_prebuffering) {
            app_audio_recorder_stream_free(chunk);
            continue;
        }
        if (xRingbufferSend(s_mic_local_rb, chunk, recv_len, pdMS_TO_TICKS(GW_AUDIO_LOCAL_RB_PUSH_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "[V2_WATCHER_VOICE_RUNTIME] local_rb_overflow dropped_len=%d", (int)recv_len);
        }
        app_audio_recorder_stream_free(chunk);
    }

    app_audio_recorder_stream_stop();
    vTaskDelete(NULL);
}
#endif /* CONFIG_GPTNIX_WATCHER_VOICE_SYNTHETIC_TEST_AUDIO */

/* Drains the local ring buffer and does the actual (blocking) WS sends -- fully decoupled from the
 * recorder's own ring buffer, so network slowness here never causes recorder-side overflow. Never logs
 * audio content. */
static void s_audio_send_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] send_task_started");

    for (;;) {
        app_gptnix_watcher_voice_state_t state = app_gptnix_watcher_voice_get_state();
        if (state != GPTNIX_WATCHER_VOICE_STATE_READY) {
            ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] send_task_ended state=%d", (int)state);
            break;
        }

        // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): live testing + Gemini Live's own
        // best-practices guidance (ai.google.dev/gemini-api/docs/live-api/best-practices) point at
        // uninterrupted delivery being what avoids audible playback gaps. The capture task already stops
        // QUEUEING new mic audio while a player stream is active, but this send task kept draining and
        // sending whatever was ALREADY backlogged in the local ring buffer regardless -- contending with
        // esp_websocket_client's shared send/receive lock for the very same connection Gemini's response
        // is arriving on, most likely the real cause of the reported ~3s/~10s speech cutouts. Left
        // in the ring buffer (not dropped) until playback finishes, then sent as normal.
        // Also checking s_prebuffering (see the matching capture-task comment) so this task stops
        // sending the instant Gemini's reply starts arriving, not just once hardware playback begins.
        if (s_player_stream_active || s_prebuffering) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        size_t item_len = 0;
        uint8_t *item = (uint8_t *)xRingbufferReceiveUpTo(s_mic_local_rb, &item_len,
            pdMS_TO_TICKS(GW_AUDIO_BRIDGE_RECV_TIMEOUT_MS), GW_AUDIO_LOCAL_RB_ITEM_MAX_BYTES);
        if (item == NULL) {
            continue;
        }
        // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test showed
        // esp_websocket_client's send path unreliable for the recorder's full chunk size (16000 raw
        // bytes, ~0.5s of audio) even with a generously enlarged buffer -- matches documented upstream
        // reliability issues with large single sends. Splitting into smaller pieces avoids that path
        // entirely, at the cost of slightly more WS messages (still well within real-time budget for
        // 16kHz/16-bit/mono audio).
        size_t offset = 0;
        while (offset < item_len) {
            size_t piece_len = item_len - offset;
            if (piece_len > GW_AUDIO_SEND_PIECE_MAX_BYTES) {
                piece_len = GW_AUDIO_SEND_PIECE_MAX_BYTES;
            }
            (void)app_gptnix_watcher_voice_send_audio(item + offset, piece_len);
            offset += piece_len;
        }
        vRingbufferReturnItem(s_mic_local_rb, item);
    }

    vTaskDelete(NULL);
}

static void s_listen_start(void)
{
    // Show the vendor's own push-to-talk/listening screen (the closest existing UI state to a listening
    // indicator -- the same VIEW_EVENT the vendor voice assistant posts when IT starts recording, before
    // we disabled it in this build). Posted to the general-purpose VIEW_EVENT_BASE bus (not GPTNiX-
    // specific), so this does not cross the M2 API boundary.
    esp_event_post_to(app_event_loop_handle, VIEW_EVENT_BASE, VIEW_EVENT_VI_RECORDING,
        NULL, 0, pdMS_TO_TICKS(1000));
    s_listening_active = true;
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] listen: start");
}

static void s_listen_stop(void)
{
    s_listening_active = false;
    ESP_LOGI(TAG, "[V2_WATCHER_VOICE_RUNTIME] listen: stop");
}

static void s_ctrl_event_handler(void *handler_args, esp_event_base_t base, int32_t id, void *event_data)
{
    (void)handler_args;
    (void)base;
    (void)event_data;
    if (id == CTRL_EVENT_GW_LISTEN_START) {
        s_listen_start();
    } else if (id == CTRL_EVENT_GW_LISTEN_STOP) {
        s_listen_stop();
    }
}

void app_gptnix_watcher_voice_runtime_start(void)
{
    s_player_stream_active = false;
    app_gptnix_watcher_voice_set_audio_callback(s_on_audio_received, NULL);

    // Knob-trigger follow-up: registered once per runtime start (this function's own existing
    // once-per-process-lifetime contract, matching s_mic_local_rb/s_player_feed_queue below).
    static bool s_ctrl_events_registered = false;
    if (!s_ctrl_events_registered) {
        esp_event_handler_register_with(app_event_loop_handle, CTRL_EVENT_BASE, CTRL_EVENT_GW_LISTEN_START,
            s_ctrl_event_handler, NULL);
        esp_event_handler_register_with(app_event_loop_handle, CTRL_EVENT_BASE, CTRL_EVENT_GW_LISTEN_STOP,
            s_ctrl_event_handler, NULL);
        s_ctrl_events_registered = true;
    }

    // Allocated once and kept for the process lifetime (matches app_audio_recorder.c's own
    // psram_malloc'd-static-ring-buffer pattern) -- simpler and safer than trying to coordinate a
    // free() between two independently-exiting tasks across repeated session start/stop cycles.
    if (s_mic_local_rb == NULL) {
        s_mic_local_rb_storage = (uint8_t *)psram_malloc(GW_AUDIO_LOCAL_RB_SIZE_BYTES);
        if (s_mic_local_rb_storage == NULL) {
            ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] local_rb_alloc_failed");
            return;
        }
        s_mic_local_rb = xRingbufferCreateStatic(GW_AUDIO_LOCAL_RB_SIZE_BYTES, RINGBUF_TYPE_BYTEBUF,
            s_mic_local_rb_storage, &s_mic_local_rb_struct);
        if (s_mic_local_rb == NULL) {
            ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] local_rb_create_failed");
            return;
        }
    }

    TaskHandle_t capture_handle = NULL;
    BaseType_t capture_created = xTaskCreate(s_audio_capture_task, "gw_audio_capture",
        GW_AUDIO_BRIDGE_TASK_STACK_BYTES, NULL, GW_AUDIO_BRIDGE_TASK_PRIO, &capture_handle);
    if (capture_created != pdPASS) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] capture_task_create_failed");
    }

    TaskHandle_t send_handle = NULL;
    BaseType_t send_created = xTaskCreate(s_audio_send_task, "gw_audio_send",
        GW_AUDIO_SEND_TASK_STACK_BYTES, NULL, GW_AUDIO_SEND_TASK_PRIO, &send_handle);
    if (send_created != pdPASS) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] send_task_create_failed");
    }

    // M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): queue-decoupled player feed -- see the
    // GW_PLAYER_FEED_* comment above. Allocated once and kept for the process lifetime, same rationale
    // as s_mic_local_rb above.
    if (s_player_feed_queue == NULL) {
        s_player_feed_queue = xQueueCreate(GW_PLAYER_FEED_QUEUE_DEPTH, sizeof(gw_player_feed_item_t));
        if (s_player_feed_queue == NULL) {
            ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] player_feed_queue_create_failed");
        }
    }
    TaskHandle_t player_feed_handle = NULL;
    BaseType_t player_feed_created = xTaskCreate(s_player_feed_task, "gw_player_feed",
        GW_PLAYER_FEED_TASK_STACK_BYTES, NULL, GW_PLAYER_FEED_TASK_PRIO, &player_feed_handle);
    if (player_feed_created != pdPASS) {
        ESP_LOGE(TAG, "[V2_WATCHER_VOICE_RUNTIME] player_feed_task_create_failed");
    }
}

#else

void app_gptnix_watcher_voice_runtime_start(void)
{
    /* CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME disabled: no-op. */
}

#endif /* CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME */
