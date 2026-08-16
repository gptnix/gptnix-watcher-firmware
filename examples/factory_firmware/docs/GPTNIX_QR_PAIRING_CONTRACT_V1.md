# GPTNiX Watcher QR Pairing Transport Contract — v1

**Status:** locked for the foundation slice (`app_gptnix_qr_pair.c/.h`).
**Scope:** this file is a **transport contract only**. It does not define a new
backend pairing owner. The canonical pairing state machine, secret issuance,
and expiry/consumption semantics remain owned exclusively by the GPTNiX V2
backend (`src/v2/application/WatcherPairingService.js`,
`src/v2/routes/v2WatcherPairing.js`). The device never reinterprets or
second-guesses that ownership.

## QR payload envelope

The QR code encodes exactly one UTF-8 JSON object, with exactly these three
top-level keys and no others:

```json
{"schemaVersion":1,"pairingId":"<opaque-string>","pairingValue":"<opaque-string>"}
```

## Field rules

- `schemaVersion` — required, must be the mathematically exact integer `1`.
  A JSON number that is not an exact integer (e.g. `1.5`) is rejected. No
  other schema version is accepted by this foundation slice.
- `pairingId` — required, non-empty UTF-8 string, at most 128 bytes.
- `pairingValue` — required, non-empty UTF-8 string, at most 256 bytes.
  This value is a **backend-owned opaque secret**. The device never inspects,
  interprets, or derives meaning from its contents beyond copying it.
- No extra top-level keys are permitted. A payload with any key other than
  `schemaVersion`, `pairingId`, `pairingValue` is rejected.
- The entire decoded QR text payload (`data.payload` from quirc) must not
  exceed 512 bytes. Anything larger is rejected before JSON parsing is
  attempted.

## Frame acceptance rules

- Exactly one QR code must be present in an accepted camera frame.
- Zero QR codes detected → no result (`GPTNIX_QR_PAIR_RESULT_NO_CODE`).
- More than one QR code detected → ambiguous, fail closed
  (`GPTNIX_QR_PAIR_RESULT_AMBIGUOUS`). The device never guesses which code is
  the intended pairing code.
- Malformed JSON, wrong key set, or any field-rule violation above → fail
  closed (`GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD`). No partially-populated
  output is ever produced.

## Backend remains the sole owner of secret-state classification

The device does not infer expiry, consumption, or validity of a
`pairingId`/`pairingValue` pair from anything other than the backend's own
response to `POST /v2/watcher/pairing/complete`. This foundation slice does
not call that endpoint — it only produces a validated, RAM-only payload for a
future runtime task to hand to the canonical pairing transport layer.

## Logging / persistence invariants

- The raw QR text, the parsed JSON, `pairingId`, and `pairingValue` must never
  appear in any log line, at any log level, in this module or any module that
  consumes its output.
- `pairingId`/`pairingValue` are never written to NVS, flash, SPIFFS, or any
  other persistent storage by this module.

## Approved future security posture (recorded here as an invariant, not implemented by this slice)

```text
first-voice token storage = RAM only
NVS token write forbidden
reboot loses auth and requires re-pair
PoP (proof-of-possession) omission is approved ONLY for a controlled,
  canary-only first-voice slice
production persistent auth storage requires flash/NVS encryption
production requires a provisioned device PoP mechanism before general rollout
```

This contract file records that approved future regime so later milestones
cannot silently relax it. It grants no exception for this foundation slice,
which itself performs zero persistence and zero network calls.
