# GPTNiX Watcher Realtime Voice — WSS Transport/Session Contract — v1

**Status:** locked for the M2 foundation slice (`app_gptnix_watcher_voice.c/.h`).
**Milestone:** M2_FIRST_VOICE_FIRMWARE_FOUNDATION.
**Scope:** this file is a **firmware transport consumption contract only**. It
does not define a new backend contract owner — the backend's
`docs/v2/V2_WATCHER_GEMINI_LIVE_CONTRACT_2026-08-15.md` (canonical owner:
`GeminiLiveTokenBroker.js`) remains the sole owner of the session DTO shape,
model, voice, system instruction, and auth-placement decision. This document
only locks how firmware consumes that already-decided contract.

## Feature gate

```text
CONFIG_GPTNIX_WATCHER_VOICE, default OFF (n)
```

`app_gptnix_watcher_voice.c/.h` is the ONE canonical firmware owner for the
GPTNiX Gemini Live WebSocket transport/session lifecycle. No second WSS
owner may be introduced.

## Ownership boundaries — backend decides, firmware transports

```text
model owner        = backend (GeminiLiveTokenBroker.js)
voice owner         = backend
system instruction   = backend
auth placement        = backend (currently: Authorization header, "Token" scheme)
```

Firmware never independently generates or overrides model/voice/system
instruction/auth placement. `app_gptnix_watcher_voice_prepare_session()`
only validates that the backend's own DTO is internally consistent
(`setup.setup.model == "models/" + top-level model`) — this is a consistency
check, not a firmware-side model decision.

## client.setup serialization invariant

The backend DTO's `client.setup` field is serialized **exactly as-is** and
sent as the WebSocket text message body:

```text
wire message = JSON.stringify(client.setup)
```

Firmware must NEVER send `client.setup.setup` directly (that would omit the
required outer `{"setup": ...}` wrapper) and must NEVER wrap `client.setup`
in another `{"setup": ...}` layer (that would double-wrap it). The apparent
"double setup" in the backend DTO's own field path (`client.setup.setup.model`)
is only a JS/C property-path artifact of how the backend names its own
fields — `client.setup` itself, serialized verbatim, already has the correct
single-level `{"setup": {...}}` wire shape per the current official Gemini
Live raw WebSocket protocol.

## Authentication — Authorization header only

```text
Authorization: Token <ephemeral-token>
```

The ephemeral token is never placed in the WebSocket URI/query string. This
firmware module only accepts a session DTO whose `client.auth` object has
exactly `type=ephemeral_token`, `placement=header`, `header=Authorization`,
`scheme=Token`, and a non-empty `token`; a legacy `parameter` (query-auth)
field, if present, causes the DTO to be rejected. Firmware never chooses a
different auth placement than what the backend DTO specifies.

TLS certificate verification always uses `esp_crt_bundle_attach`. Firmware
never sets `skip_cert_common_name_check`, never uses insecure TLS, and never
uses plaintext `ws://`.

## setup / setupComplete handshake

```text
1. WEBSOCKET_EVENT_CONNECTED -> send client.setup verbatim, exactly once, no retry
2. wait for a complete server text message
3. accept ONLY {"setupComplete":{}} (exactly one top-level key, value is an object)
   before transitioning to READY
4. any other complete message before READY -> PROTOCOL_ERROR
```

No second setup message is ever sent, even if the server sends an
unexpected message first — an unexpected pre-READY message is a protocol
error, not a retry trigger.

## Fragmented TEXT reassembly

Data delivered across multiple `WEBSOCKET_EVENT_DATA` events is reassembled
using `payload_offset`/`payload_len`/`data_len`/`fin`, bounded to 8192 bytes
total. The first fragment of a new payload must have `payload_offset == 0`
and a text opcode; every subsequent fragment's offset must exactly match the
bytes already accumulated. Any offset mismatch, oversized payload, or
non-text first fragment before READY is a protocol error. The buffer is
NUL-terminated and JSON-parsed only after the complete payload has been
proven fully assembled and within bounds.

## No auto-reconnect

`disable_auto_reconnect = true`. On CLOSED/DISCONNECTED/ERROR, the module
sets a terminal state and never creates a new client automatically. The
`esp_websocket_client_stop()` API must never be called from the module's own
event handler (per the component's own documented restriction) — only
caller-context `disconnect()`/`deinit()` may stop/destroy the client.

## No audio, no Firebase/pairing, in M2

This module never constructs a `realtimeInput`/audio message, never decodes
server audio, never calls the microphone/speaker owners
(`app_audio_recorder.c`, `app_audio_player.c`), and never calls Firebase
Identity Toolkit, `pairing/start`, `pairing/complete`, or
`POST /v2/watcher/realtime/session`. All of those remain a later milestone's
scope. **M2 is a source/build/contract proof only — it is NOT physical
runtime proof.** No real WSS handshake, no real `setupComplete`, no real
microphone/speaker audio has been exercised by this milestone.

## RAM-only session material, secret zeroization

All session material (endpoint, token, setup JSON, RX reassembly buffer) is
RAM-only, module-owned, and explicitly zeroized (`mbedtls_platform_zeroize`)
once no longer needed, on every return path — not only the success path.
This module never writes to NVS.

## Third-party header-copy residual RAM limitation

`esp_websocket_client_append_header()` copies the appended `Authorization`
header value into the library's own heap-owned internal state. This
module's own temporary "Token \<token\>" buffer is zeroized immediately
after the append call returns, but the library's internal copy is released
(freed, not cryptographically zeroized) only when the client is destroyed.
This is a documented residual RAM-lifetime limitation of the
`espressif/esp_websocket_client` canary transport library — this module
cannot patch third-party component internals in M2, and this limitation is
recorded here rather than silently hidden or falsely claimed as solved.

## Not claimed by M2

```text
real WSS handshake
real Gemini setupComplete
real backend session HTTP request
real Firebase auth
real microphone audio
real speaker audio
reconnect under Wi-Fi loss
TLS heap peak
runtime fragmentation
physical Watcher heap stability
```

These remain M3+ scope, requiring separate explicit physical-device
authorization.
