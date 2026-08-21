/**
 * GPTNiX Watcher M3C runtime audio bridge entry point.
 *
 * See plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md. Starts the mic-feeding FreeRTOS
 * task that streams captured microphone audio into an already-READY Gemini
 * Live WS session (owned by app_gptnix_watcher_voice.c). This is the ONE
 * caller of the audio recorder API on the M3A provisioning success path,
 * kept in its own translation unit so app_gptnix_watcher_provision.c itself
 * never references the microphone/recorder APIs (a fitness-enforced
 * separation-of-concerns boundary predating this milestone).
 */
#ifndef APP_GPTNIX_WATCHER_VOICE_RUNTIME_H
#define APP_GPTNIX_WATCHER_VOICE_RUNTIME_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Starts the mic-feeding task. Caller must have already reached a READY
 * Gemini Live WS session (see app_gptnix_watcher_voice_get_state()) before
 * calling this -- the task itself re-checks state each loop iteration and
 * exits cleanly once the session is no longer READY. No-op (compiles to an
 * empty function) when CONFIG_GPTNIX_WATCHER_VOICE_RUNTIME is disabled.
 */
void app_gptnix_watcher_voice_runtime_start(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_GPTNIX_WATCHER_VOICE_RUNTIME_H */
