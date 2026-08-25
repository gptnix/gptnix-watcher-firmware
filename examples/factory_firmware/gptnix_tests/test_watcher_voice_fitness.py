#!/usr/bin/env python3
"""GPTNiX Watcher realtime-voice WSS/session foundation — source/architecture
fitness test (M2). Python standard library only, no pip dependency.

This is a STATIC SOURCE proof, not a runtime/physical proof: it never
builds, flashes, or executes firmware. It exits non-zero if any invariant
below is violated. It combines semantic source checks with Git blob-identity
checks against immutable, Phase-A-proven blob IDs to prove protected files
are genuinely byte-identical to DEVELOPMENT_BASE_SHA a27210a8dd738f2c9241234820dce69a8a8de480
(not merely unmentioned in comments).

CI portability note: the CI checkout for this repo intentionally uses
`fetch-depth: 1` (see .github/workflows/gptnix-firmware-build.yml), so the
base commit object is NOT reachable in that runner. Protected-file checks
therefore must never dereference BASE_SHA through any git command (no
`git diff BASE_SHA`, `git show BASE_SHA`, `git cat-file BASE_SHA`,
`git rev-parse BASE_SHA`) at runtime. Instead they compare the Git blob
identity of the current on-disk file bytes (computed locally, requiring no
history) against an immutable blob ID captured once, out-of-band, from the
canonical base and embedded below as a constant. This principle mirrors the
same shallow-clone-safe policy already used by test_qr_pairing_fitness.py's
structural-presence checks -- this file previously violated that policy for
checks #42-46 and was corrected to fix it.
"""
import hashlib
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FACTORY_DIR = os.path.dirname(SCRIPT_DIR)  # .../examples/factory_firmware
REPO_ROOT = os.path.dirname(os.path.dirname(FACTORY_DIR))  # repo root

BASE_SHA = "a27210a8dd738f2c9241234820dce69a8a8de480"

APP_C = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_voice.c")
APP_H = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_voice.h")
CONTRACT_MD = os.path.join(FACTORY_DIR, "docs", "GPTNIX_WATCHER_VOICE_TRANSPORT_CONTRACT_V1.md")
KCONFIG = os.path.join(FACTORY_DIR, "main", "Kconfig.projbuild")
IDF_COMPONENT_YML = os.path.join(FACTORY_DIR, "main", "idf_component.yml")
CMAKELISTS = os.path.join(FACTORY_DIR, "main", "CMakeLists.txt")
MAIN_C = os.path.join(FACTORY_DIR, "main", "main.c")
AUDIO_RECORDER_C = os.path.join(FACTORY_DIR, "main", "app", "app_audio_recorder.c")
AUDIO_RECORDER_H = os.path.join(FACTORY_DIR, "main", "app", "app_audio_recorder.h")
AUDIO_PLAYER_C = os.path.join(FACTORY_DIR, "main", "app", "app_audio_player.c")
AUDIO_PLAYER_H = os.path.join(FACTORY_DIR, "main", "app", "app_audio_player.h")
VOICE_INTERACTION_C = os.path.join(FACTORY_DIR, "main", "app", "app_voice_interaction.c")

FAILURES = []


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def check(name):
    def decorator(fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001 - report as failure, not crash
            ok, detail = False, "exception: %r" % (exc,)
        status = "PASS" if ok else "FAIL"
        print("[%s] %s%s" % (status, name, (" -- " + detail) if detail else ""))
        if not ok:
            FAILURES.append(name)
        return fn
    return decorator


# Immutable Git blob IDs of the exact protected files at DEVELOPMENT_BASE_SHA
# a27210a8dd738f2c9241234820dce69a8a8de480, captured out-of-band via:
#   git rev-parse "$BASE_SHA:<relative-path>"
# and independently cross-checked against the current worktree via:
#   git hash-object --no-filters "<relative-path>"
# before being embedded here. They intentionally avoid parent/base history
# at runtime because CI uses fetch-depth:1.
PROTECTED_BASE_BLOBS = {
    "examples/factory_firmware/main/CMakeLists.txt":
        "6663576a37eb11b5ae0ef8494fa6cd4238bdd590",
    "examples/factory_firmware/main/app/app_audio_recorder.c":
        "8cfb5065e89248e6ed9d9fce3f5fcd4ec58257f3",
    "examples/factory_firmware/main/app/app_audio_recorder.h":
        "9a209cb303e02fdb0828a8050d8cbb018af60052",
    "examples/factory_firmware/main/app/app_audio_player.c":
        "bb0bc1bb478de19b625326226c548504d06a20c2",
    "examples/factory_firmware/main/app/app_audio_player.h":
        "8a0b8485a102aa0ec98f3b1634a03ae3c0491eb1",
    "examples/factory_firmware/main/app/app_voice_interaction.c":
        "7869b7d1257135c6d38e41a77f0f92c6b6d36e49",
}


def _working_tree_git_blob_sha(path_rel):
    """Git blob SHA-1 of the current on-disk file, computed locally from its
    bytes using the Git blob object formula (sha1("blob " + len + "\\0" +
    data)) -- requires no git invocation, no network, and no repository
    history of any depth. Returns None (fail closed) if the file is missing
    or unreadable, never an exception that a caller could misclassify."""
    abs_path = os.path.join(REPO_ROOT, path_rel)
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _protected_file_matches_base(path_rel):
    """True only if the current working-tree file's Git blob identity
    matches the immutable base blob ID captured in PROTECTED_BASE_BLOBS. A
    missing/unreadable file or a hash mismatch both fail closed to False --
    there is no exception path that could be silently misread as "changed"
    versus an infrastructure error, because there is no infrastructure
    dependency (no subprocess, no git, no BASE_SHA dereference) left here at
    all."""
    expected = PROTECTED_BASE_BLOBS.get(path_rel)
    if expected is None:
        return False
    actual = _working_tree_git_blob_sha(path_rel)
    return actual == expected


# 1. header + source files exist
@check("1. header + source files exist")
def _c1():
    missing = [p for p in (APP_C, APP_H) if not os.path.isfile(p)]
    return not missing, "missing: %s" % missing


# 2. contract doc exists
@check("2. contract doc exists")
def _c2():
    return os.path.isfile(CONTRACT_MD), ""


# 3. CONFIG_GPTNIX_WATCHER_VOICE exists exactly once, default n
@check("3. CONFIG_GPTNIX_WATCHER_VOICE exists exactly once and default n")
def _c3():
    text = _read(KCONFIG)
    matches = re.findall(r"^\s*config\s+GPTNIX_WATCHER_VOICE\s*$", text, re.MULTILINE)
    if len(matches) != 1:
        return False, "found %d" % len(matches)
    m = re.search(r"config\s+GPTNIX_WATCHER_VOICE\s*\n(.*?)(?=\n\s*config\s|\nendmenu)", text, re.DOTALL)
    if not m:
        return False, "block not found"
    return bool(re.search(r"^\s*default\s+n\s*$", m.group(1), re.MULTILINE)), m.group(1).strip()[:60]


# 4. idf_component.yml pins espressif/esp_websocket_client exactly "1.7.0"
@check("4. idf_component.yml pins espressif/esp_websocket_client exactly 1.7.0")
def _c4():
    text = _read(IDF_COMPONENT_YML)
    matches = re.findall(r'espressif/esp_websocket_client:\s*["\']1\.7\.0["\']', text)
    return len(matches) == 1, "found %d" % len(matches)


# 5. no version range/latest/caret used for websocket dependency
@check("5. no version range/latest/caret for websocket dependency")
def _c5():
    text = _read(IDF_COMPONENT_YML)
    m = re.search(r"espressif/esp_websocket_client:\s*[\"']([^\"']+)[\"']", text)
    if not m:
        return False, "dependency line not found"
    value = m.group(1)
    bad = any(s in value for s in ("^", ">=", "<=", "~", "latest", "*"))
    return (not bad) and value == "1.7.0", "value=%r" % value


# 6. public API contains exactly the required symbols
@check("6. public API contains exactly the required init/deinit/prepare/connect/disconnect/get_state symbols")
def _c6():
    text = _read(APP_H)
    required = [
        "app_gptnix_watcher_voice_init",
        "app_gptnix_watcher_voice_deinit",
        "app_gptnix_watcher_voice_prepare_session",
        "app_gptnix_watcher_voice_connect",
        "app_gptnix_watcher_voice_disconnect",
        "app_gptnix_watcher_voice_get_state",
    ]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 7. no public token getter exists
@check("7. no public token getter exists")
def _c7():
    text = _read(APP_H)
    hits = [s for s in ("get_token", "token_getter", "_token(void)") if s in text]
    return not hits, "found: %s" % hits


# 8. module uses esp_crt_bundle_attach
@check("8. module uses esp_crt_bundle_attach")
def _c8():
    return "esp_crt_bundle_attach" in _read(APP_C), ""


# 9. module never sets skip_cert_common_name_check true
@check("9. module never sets skip_cert_common_name_check true")
def _c9():
    text = _read(APP_C)
    return "skip_cert_common_name_check" not in text, ""


# 10-12. auth placement/header/scheme literal requirements present
@check("10. module requires auth placement \"header\"")
def _c10():
    text = _read(APP_C)
    return '"header") != 0' in text and '"placement"' in text, ""


@check("11. module requires auth header \"Authorization\"")
def _c11():
    text = _read(APP_C)
    return '"Authorization") != 0' in text, ""


@check("12. module requires auth scheme \"Token\"")
def _c12():
    text = _read(APP_C)
    return '"Token") != 0' in text, ""


# 13. legacy `parameter` auth field is rejected/absent in accepted contract
@check("13. legacy `parameter` auth field is rejected/absent in accepted contract")
def _c13():
    text = _read(APP_C)
    return 'cJSON_HasObjectItem(auth_item, "parameter")' in text, ""


# 14. source never appends token/access_token to endpoint URI
@check("14. source never appends token/access_token to endpoint URI")
def _c14():
    text = _read(APP_C)
    hits = re.findall(r"strcat\([^)]*endpoint", text)
    has_query_reject = 'strstr(endpoint_str, "access_token=")' in text
    return (not hits) and has_query_reject, "concat_hits=%s query_reject_present=%s" % (hits, has_query_reject)


# 15. source uses esp_websocket_client_append_header(... "Authorization" ...)
@check("15. source uses esp_websocket_client_append_header with Authorization")
def _c15():
    text = _read(APP_C)
    return 'esp_websocket_client_append_header(s_ctx->ws_client, "Authorization", auth_value)' in text, ""


# 16. source zeroizes temporary auth value
@check("16. source zeroizes temporary auth value")
def _c16():
    text = _read(APP_C)
    return "mbedtls_platform_zeroize(auth_value, sizeof(auth_value))" in text, ""


# 17. source zeroizes persistent firmware-owned token on cleanup
@check("17. source zeroizes persistent firmware-owned token on cleanup")
def _c17():
    text = _read(APP_C)
    return "mbedtls_platform_zeroize(ctx->token, sizeof(ctx->token))" in text, ""


# 18. source uses cJSON_ParseWithLengthOpts for session DTO
@check("18. source uses cJSON_ParseWithLengthOpts for session DTO")
def _c18():
    text = _read(APP_C)
    return "cJSON_ParseWithLengthOpts(dto_copy, session_len + 1, &parse_end, 1)" in text, ""


# 19. source explicitly rejects embedded NUL in session DTO
@check("19. source explicitly rejects embedded NUL in session DTO")
def _c19():
    text = _read(APP_C)
    return "memchr(session_json, '\\0', session_len)" in text, ""


# 20. source checks full JSON consumption
@check("20. source checks full JSON consumption")
def _c20():
    text = _read(APP_C)
    hits = len(re.findall(r"full_consumption", text))
    return hits >= 2, "full_consumption occurrences=%d" % hits


# 21. source serializes `client.setup` object, not `client.setup.setup` as wire root
@check("21. source serializes client.setup object (not client.setup.setup) as wire root")
def _c21():
    text = _read(APP_C)
    has_correct = "cJSON_PrintUnformatted(setup_item)" in text
    has_wrong = bool(re.search(r"cJSON_Print\w*\(\s*inner_setup\s*\)", text))
    return has_correct and not has_wrong, "correct=%s wrong_found=%s" % (has_correct, has_wrong)


# 22. source has exactly one setup send call site
@check("22. source has exactly one setup send call site")
def _c22():
    text = _read(APP_C)
    hits = len(re.findall(r"esp_websocket_client_send_text\(", text))
    # M3C (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): 3 legitimate call sites -- the original setup message
    # send (WEBSOCKET_EVENT_CONNECTED), app_gptnix_watcher_voice_send_audio()'s realtimeInput send, and
    # (follow-up) app_gptnix_watcher_voice_send_text_turn()'s clientContent send (test/diagnostic-only,
    # never called from the normal microphone-streaming path) -- all through this module's own single
    # private ws_client (never exposed externally).
    return hits == 3, "found %d" % hits


# 23. source waits for setupComplete before READY
@check("23. source waits for setupComplete before READY")
def _c23():
    text = _read(APP_C)
    return '"setupComplete"' in text and "GPTNIX_WATCHER_VOICE_STATE_READY" in text, ""


# 24-28. exact bound constants
@check("24. source bounds session DTO <=65536")
def _c24():
    return "GPTNIX_WATCHER_VOICE_SESSION_DTO_MAX_BYTES   (65536)" in _read(APP_C), ""


@check("25. source bounds endpoint <=512")
def _c25():
    return "GPTNIX_WATCHER_VOICE_ENDPOINT_MAX_BYTES      (512)" in _read(APP_C), ""


@check("26. source bounds token <=2048")
def _c26():
    return "GPTNIX_WATCHER_VOICE_TOKEN_MAX_BYTES         (2048)" in _read(APP_C), ""


@check("27. source bounds setup JSON <=32768")
def _c27():
    return "GPTNIX_WATCHER_VOICE_SETUP_JSON_MAX_BYTES    (32768)" in _read(APP_C), ""


@check("28. source bounds RX reassembly <=8192")
def _c28():
    # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): 8192 was sized for the tiny (~26-byte)
    # setupComplete message this buffer originally only ever needed to hold. A live physical test with
    # real speech showed Gemini's actual serverContent audio response messages are far larger --
    # observed real fragments up to 33547 bytes -- which the 8192 bound was silently rejecting as a
    # protocol error, breaking every session the first time it received a real (non-empty) audio reply.
    # Enlarged to 65536 (PSRAM-allocated, MALLOC_CAP_SPIRAM -- not a scarce resource) with headroom.
    return "GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES (65536)" in _read(APP_C), ""


# 29. source uses payload_offset/payload_len/data_len/fin
@check("29. source uses payload_offset/payload_len/data_len/fin")
def _c29():
    text = _read(APP_C)
    required = ["payload_offset", "payload_len", "data_len", "->fin"]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 30. no automatic reconnect; config disable_auto_reconnect=true
@check("30. no automatic reconnect; config disable_auto_reconnect=true")
def _c30():
    text = _read(APP_C)
    return "config.disable_auto_reconnect = true" in text, ""


# 31. event callback does NOT call esp_websocket_client_stop
@check("31. event callback does NOT call esp_websocket_client_stop")
def _c31():
    text = _read(APP_C)
    m = re.search(r"static void s_ws_event_handler\(.*?\n\}\n", text, re.DOTALL)
    if not m:
        return False, "event handler body not found"
    return "esp_websocket_client_stop" not in m.group(0), ""


# 32-33. no mic/player API references
@check("32. no microphone APIs referenced")
def _c32():
    text = _read(APP_C)
    hits = [s for s in ("app_audio_recorder_stream_recv", "app_audio_recorder_stream_start",
                         "app_audio_recorder_stream_stop", "app_audio_recorder_init") if s in text]
    return not hits, "found: %s" % hits


@check("33. no player APIs referenced")
def _c33():
    text = _read(APP_C)
    hits = [s for s in ("app_audio_player_stream_send", "app_audio_player_stream_init",
                         "app_audio_player_stream_start", "app_audio_player_init") if s in text]
    return not hits, "found: %s" % hits


# 34. realtimeInput audio construction is scoped to exactly one call site
@check("34. realtimeInput audio construction is scoped to exactly one call site")
def _c34():
    # M3C (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): this module's own header always described "runtime
    # audio wiring" as "a separate, later milestone" -- that milestone has arrived. realtimeInput
    # construction is now an intentional, in-scope part of this module (app_gptnix_watcher_voice_send_audio),
    # reusing the module's own private ws_client rather than exposing it externally. The invariant is
    # narrowed from "never present" to "present exactly once" -- still catches accidental duplication.
    text = _read(APP_C)
    hits = len(re.findall(r'"realtimeInput"', text))
    return hits == 1, "found %d" % hits


# 35. no Firebase URLs/functions
@check("35. no Firebase URLs/functions")
def _c35():
    text = _read(APP_C).lower()
    hits = [s for s in ("identitytoolkit", "securetoken", "firebase") if s in text]
    return not hits, "found: %s" % hits


# 36. no pairing route strings
@check("36. no pairing route strings")
def _c36():
    text = _read(APP_C)
    hits = [s for s in ("pairing/start", "pairing/complete", "pairing/unpair", "pairing/status") if s in text]
    return not hits, "found: %s" % hits


# 37. no NVS token write APIs
@check("37. no NVS token write APIs")
def _c37():
    text = _read(APP_C)
    hits = [s for s in ("nvs_set", "nvs_open", "nvs_commit") if s in text]
    return not hits, "found: %s" % hits


# 38. no QR/camera/SSCMA callback registration
@check("38. no QR/camera/SSCMA callback registration")
def _c38():
    text = _read(APP_C)
    hits = [s for s in ("sscma_client_register_callback", "bsp_sscma_client_init", "quirc_", "app_gptnix_qr_pair") if s in text]
    return not hits, "found: %s" % hits


# 39. no GEMINI_API_KEY literal/owner in firmware
@check("39. no GEMINI_API_KEY literal/owner in firmware")
def _c39():
    return "GEMINI_API_KEY" not in _read(APP_C), ""


# 40. no hardcoded gemini-3.1-flash-live-preview in firmware source
@check("40. no hardcoded gemini-3.1-flash-live-preview in firmware source")
def _c40():
    return "gemini-3.1-flash-live-preview" not in _read(APP_C), ""


# 41. no voice name hardcoded in firmware source
@check("41. no voice name hardcoded in firmware source")
def _c41():
    text = _read(APP_C)
    hits = [s for s in ("Charon", "Kore", "voiceName") if s in text]
    return not hits, "found: %s" % hits


# 42. main.c: M3A-aware supersession of the original "main.c untouched" invariant. M3A (M3A.3B) legitimately
# gives main.c its own compile-gated runtime integration call site -- a byte-identical-to-base check would
# now produce a false failure on a real, authorized architecture milestone. The invariant this check actually
# protects -- "main.c never calls the M2 realtime-voice transport API directly" -- still holds and is proven
# here directly against current source (main.c's own runtime integration is app_gptnix_watcher_provision_run,
# which is the sole authorized caller of that API; see test_watcher_m3a_provision_fitness.py checks #23-26 for
# the compile-gating/single-call-site proof). main.c's blob identity is intentionally no longer pinned here.
@check("42. main.c has zero direct calls into the M2 realtime-voice transport API")
def _c42():
    text = _read(MAIN_C) if os.path.isfile(MAIN_C) else ""
    return "app_gptnix_watcher_voice" not in text, ""


@check("43. CMakeLists.txt untouched")
def _c43():
    return _protected_file_matches_base("examples/factory_firmware/main/CMakeLists.txt"), ""


@check("44. app_audio_recorder.c/.h untouched")
def _c44():
    a = _protected_file_matches_base("examples/factory_firmware/main/app/app_audio_recorder.c")
    b = _protected_file_matches_base("examples/factory_firmware/main/app/app_audio_recorder.h")
    return a and b, "c=%s h=%s" % (a, b)


@check("45. app_audio_player.c/.h untouched")
def _c45():
    a = _protected_file_matches_base("examples/factory_firmware/main/app/app_audio_player.c")
    b = _protected_file_matches_base("examples/factory_firmware/main/app/app_audio_player.h")
    return a and b, "c=%s h=%s" % (a, b)


@check("46. app_voice_interaction.c untouched")
def _c46():
    return _protected_file_matches_base("examples/factory_firmware/main/app/app_voice_interaction.c"), ""


# 47. feature OFF public path returns DISABLED deterministically
@check("47. feature OFF public path returns DISABLED deterministically")
def _c47():
    text = _read(APP_C)
    m = re.search(r"#else\s*/\*\s*!CONFIG_GPTNIX_WATCHER_VOICE\s*\*/(.*?)#endif", text, re.DOTALL)
    if not m:
        return False, "disabled region not found"
    region = m.group(1)
    disabled_count = region.count("GPTNIX_WATCHER_VOICE_RESULT_DISABLED")
    return disabled_count >= 3, "DISABLED occurrences in disabled region=%d" % disabled_count


# 48. logs never format endpoint/token/session/setup/server payload with %s
@check("48. logs never format endpoint/token/session/setup/server payload with %s")
def _c48():
    text = _read(APP_C)
    offending = [ln for ln in text.splitlines() if "ESP_LOG" in ln and "%s" in ln]
    return not offending, "lines: %s" % offending


# 49. one singleton transport owner only
@check("49. one singleton transport owner only")
def _c49():
    text = _read(APP_C)
    hits = len(re.findall(r"static struct app_gptnix_watcher_voice \*s_ctx", text))
    ws_client_fields = len(re.findall(r"esp_websocket_client_handle_t\s+\w+;", text))
    return hits == 1 and ws_client_fields == 1, "s_ctx_decls=%d ws_client_fields=%d" % (hits, ws_client_fields)


# 50. contract doc states M2 runtime/live proof is NOT claimed
@check("50. contract doc states M2 runtime/live proof is NOT claimed")
def _c50():
    text = _read(CONTRACT_MD)
    required = ["NOT", "runtime"]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 51. raw session DTO copy is zeroized before free
@check("51. raw session DTO copy is zeroized before free")
def _c51():
    text = _read(APP_C)
    zeroize_idx = text.find("mbedtls_platform_zeroize(dto_copy, session_len + 1)")
    free_idx = text.find("free(dto_copy)")
    if zeroize_idx < 0 or free_idx < 0:
        return False, "zeroize_idx=%d free_idx=%d" % (zeroize_idx, free_idx)
    return zeroize_idx < free_idx, "zeroize_idx=%d free_idx=%d" % (zeroize_idx, free_idx)


# 52. parsed session cJSON valuestrings are zeroized before cJSON_Delete
@check("52. parsed session cJSON valuestrings are zeroized before cJSON_Delete")
def _c52():
    text = _read(APP_C)
    required = [
        "s_zeroize_cjson_valuestrings",
        "s_sensitive_cjson_delete",
        "s_sensitive_cjson_delete(&root)",
    ]
    missing = [s for s in required if s not in text]
    raw_delete_hits = re.findall(r"\bcJSON_Delete\(root\)", text)
    return (not missing) and not raw_delete_hits, "missing=%s raw_delete_hits=%s" % (missing, raw_delete_hits)


# 53. cJSON printed setup string is zeroized before cJSON_free on every path
@check("53. cJSON printed setup string is zeroized before cJSON_free on every path")
def _c53():
    text = _read(APP_C)
    required = [
        "s_sensitive_cjson_free_string",
        "mbedtls_platform_zeroize(*value, len + 1)",
    ]
    missing = [s for s in required if s not in text]
    # The helper's own body owns the one legitimate direct cJSON_free(*value)
    # call; every other call site must go through s_sensitive_cjson_free_string.
    direct_printed_free = len(re.findall(r"\bcJSON_free\(printed\)", text))
    helper_owns_free = "cJSON_free(*value)" in text
    ok = (not missing) and direct_printed_free == 0 and helper_owns_free
    return ok, "missing=%s direct_printed_free=%d helper_owns_free=%s" % (missing, direct_printed_free, helper_owns_free)


# 54. setupComplete requires an empty object before READY
@check("54. setupComplete requires an empty object before READY")
def _c54():
    text = _read(APP_C)
    required = [
        'strcmp(child->string, "setupComplete") == 0',
        "cJSON_IsObject(child)",
        "child->child == NULL",
        "key_count == 1",
    ]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 55. prepare_session requires IDLE and no existing ws_client before parsing
@check("55. prepare_session requires IDLE and no existing ws_client before parsing")
def _c55():
    text = _read(APP_C)
    func_start = text.find("app_gptnix_watcher_voice_prepare_session(\n    const char *session_json")
    if func_start < 0:
        return False, "prepare_session definition not found"
    malloc_idx = text.find("heap_caps_malloc(session_len + 1", func_start)
    if malloc_idx < 0:
        return False, "heap_caps_malloc(session_len + 1 not found after function start"
    region = text[func_start:malloc_idx]
    has_state_guard = "s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_IDLE" in region
    has_ws_guard = "s_ctx->ws_client != NULL" in region
    return has_state_guard and has_ws_guard, "state_guard=%s ws_guard=%s" % (has_state_guard, has_ws_guard)


# 56. connect requires SESSION_READY and no existing ws_client
@check("56. connect requires SESSION_READY and no existing ws_client")
def _c56():
    text = _read(APP_C)
    func_start = text.find("app_gptnix_watcher_voice_connect(void)\n{")
    if func_start < 0:
        return False, "connect() definition not found"
    init_idx = text.find("esp_websocket_client_init(&config)", func_start)
    if init_idx < 0:
        return False, "esp_websocket_client_init(&config) not found after function start"
    region = text[func_start:init_idx]
    has_state_guard = "s_ctx->state != GPTNIX_WATCHER_VOICE_STATE_SESSION_READY" in region
    has_ws_guard = "s_ctx->ws_client != NULL" in region
    return has_state_guard and has_ws_guard, "state_guard=%s ws_guard=%s" % (has_state_guard, has_ws_guard)


def _connect_function_region(text):
    func_start = text.find("app_gptnix_watcher_voice_connect(void)\n{")
    func_end = text.find("\napp_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_disconnect", func_start)
    if func_start < 0 or func_end < 0:
        return None
    return text[func_start:func_end]


# 57. auth-format and websocket-init failures clear session material
@check("57. auth-format and websocket-init failures clear session material")
def _c57():
    text = _read(APP_C)
    region = _connect_function_region(text)
    if region is None:
        return False, "connect() region not found"
    helper_defined = (
        "static app_gptnix_watcher_voice_result_t s_fail_before_running_client" in text
        and "s_clear_session_material(ctx)" in text
    )
    auth_fail_idx = region.find("if (written < 0 || (size_t)written >= sizeof(auth_value))")
    ws_init_fail_idx = region.find("if (s_ctx->ws_client == NULL) {")
    if auth_fail_idx < 0 or ws_init_fail_idx < 0:
        return False, "auth_fail_idx=%d ws_init_fail_idx=%d" % (auth_fail_idx, ws_init_fail_idx)
    auth_block = region[auth_fail_idx:auth_fail_idx + 400]
    ws_init_block = region[ws_init_fail_idx:ws_init_fail_idx + 400]
    call = "s_fail_before_running_client(s_ctx, GPTNIX_WATCHER_VOICE_RESULT_WS_INIT_FAILED)"
    auth_ok = call in auth_block
    ws_init_ok = call in ws_init_block
    return (helper_defined and auth_ok and ws_init_ok), \
        "helper_defined=%s auth_ok=%s ws_init_ok=%s" % (helper_defined, auth_ok, ws_init_ok)


# 58. append-header and event-registration failures destroy client then clear session
@check("58. append-header and event-registration failures destroy client then clear session")
def _c58():
    text = _read(APP_C)
    region = _connect_function_region(text)
    if region is None:
        return False, "connect() region not found"
    header_fail_idx = region.find("if (header_err != ESP_OK) {")
    reg_fail_idx = region.find("if (reg_err != ESP_OK) {")
    if header_fail_idx < 0 or reg_fail_idx < 0:
        return False, "header_fail_idx=%d reg_fail_idx=%d" % (header_fail_idx, reg_fail_idx)
    header_block = region[header_fail_idx:header_fail_idx + 400]
    reg_block = region[reg_fail_idx:reg_fail_idx + 400]

    def destroy_before_clear(block):
        destroy_idx = block.find("esp_websocket_client_destroy(s_ctx->ws_client)")
        null_idx = block.find("s_ctx->ws_client = NULL;")
        clear_idx = block.find("s_fail_before_running_client(")
        if destroy_idx < 0 or null_idx < 0 or clear_idx < 0:
            return False
        return destroy_idx < null_idx < clear_idx

    header_ok = destroy_before_clear(header_block)
    reg_ok = destroy_before_clear(reg_block)
    return header_ok and reg_ok, "header_ok=%s reg_ok=%s" % (header_ok, reg_ok)


# 59. module-owned token is zeroized immediately after append_header and token_len reset
@check("59. module-owned token is zeroized immediately after append_header and token_len reset")
def _c59():
    text = _read(APP_C)
    region = _connect_function_region(text)
    if region is None:
        return False, "connect() region not found"
    append_idx = region.find('esp_websocket_client_append_header(s_ctx->ws_client, "Authorization", auth_value)')
    if append_idx < 0:
        return False, "append_header call not found"
    after_append = region[append_idx:]
    auth_zero_idx = after_append.find("mbedtls_platform_zeroize(auth_value, sizeof(auth_value))")
    token_zero_idx = after_append.find("mbedtls_platform_zeroize(s_ctx->token, sizeof(s_ctx->token))")
    token_len_idx = after_append.find("s_ctx->token_len = 0;")
    order_ok = (
        auth_zero_idx >= 0 and token_zero_idx >= 0 and token_len_idx >= 0
        and auth_zero_idx < token_zero_idx < token_len_idx
    )
    if not order_ok:
        return False, "auth_zero_idx=%d token_zero_idx=%d token_len_idx=%d" % (
            auth_zero_idx, token_zero_idx, token_len_idx)
    after_reset = after_append[token_len_idx + len("s_ctx->token_len = 0;"):]
    token_reads = re.findall(r"s_ctx->token\b", after_reset)
    return len(token_reads) == 0, "token_reads_after_reset=%s" % (token_reads,)


# 60. firmware contract locks one-client lifecycle and explicit M2 reinitialization before a new session
@check("60. firmware contract locks one-client lifecycle and explicit M2 reinitialization before a new session")
def _c60():
    text = _read(CONTRACT_MD)
    required = [
        "Single-client session lifecycle",
        "state==IDLE",
        "ws_client==NULL",
        "state==SESSION_READY",
        "no reset/reuse API",
        "before preparing another M2 session",
    ]
    missing = [s for s in required if s not in text]
    lowered = text.lower()
    forbidden = ["auto-reuse", "automatically reuse", "auto reset", "auto-reconnect the session"]
    forbidden_hits = [s for s in forbidden if s in lowered]
    return (not missing) and (not forbidden_hits), "missing=%s forbidden_hits=%s" % (missing, forbidden_hits)


# M3C.1A session-resumption foundation (docs/v2/V2_WATCHER_GEMINI_LIVE_SESSION_RESUMPTION_ADDENDUM_
# 2026-08-25.md). All checks below are static-source proof only, same as every check above -- no build,
# no flash, no physical/live proof claimed (M3C.1B's job).

@check("61. sessionResumptionUpdate.newHandle is only ever accepted when resumable is true")
def _c61():
    text = _read(APP_C)
    fn_start = text.find("static void s_handle_session_resumption_update(")
    if fn_start < 0:
        return False, "s_handle_session_resumption_update not found"
    fn_end = text.find("\n}\n", fn_start)
    body = text[fn_start:fn_end]
    has_resumable_check = "!resumable || new_handle == NULL || new_handle_len == 0" in body
    has_gate_before_store = body.find("!resumable") < body.find("heap_caps_malloc")
    return has_resumable_check and has_gate_before_store, "has_resumable_check=%s gate_before_store=%s" % (has_resumable_check, has_gate_before_store)


@check("62. resumption handle bytes are never passed to an ESP_LOG call")
def _c62():
    text = _read(APP_C)
    log_lines = [ln for ln in text.splitlines() if "ESP_LOG" in ln]
    offending = [ln for ln in log_lines if "resumption_handle" in ln and "%s" in ln]
    offending += [ln for ln in log_lines if "new_handle" in ln and "%s" in ln]
    handle_log_present = any("resumption_handle: updated len=%d" in ln for ln in log_lines)
    return (not offending) and handle_log_present, "offending=%s handle_log_present=%s" % (offending, handle_log_present)


@check("63. resumption_handle has exactly one struct owner and exactly one write call site")
def _c63():
    text = _read(APP_C)
    struct_decls = len(re.findall(r"char \*resumption_handle;", text))
    write_sites = len(re.findall(r"ctx->resumption_handle = ", text))
    # Exactly two writes expected: the successful-replace assignment, and NULL on clear.
    return struct_decls == 1 and write_sites == 2, "struct_decls=%d write_sites=%d" % (struct_decls, write_sites)


@check("64. old resumption handle is zeroized+freed before the replacement is installed")
def _c64():
    text = _read(APP_C)
    fn_start = text.find("static void s_handle_session_resumption_update(")
    fn_end = text.find("\n}\n", fn_start)
    body = text[fn_start:fn_end]
    zeroize_idx = body.find("mbedtls_platform_zeroize(ctx->resumption_handle")
    free_idx = body.find("free(ctx->resumption_handle)")
    install_idx = body.find("ctx->resumption_handle = replacement")
    ok = zeroize_idx >= 0 and free_idx >= 0 and install_idx >= 0 and zeroize_idx < free_idx < install_idx
    return ok, "zeroize_idx=%d free_idx=%d install_idx=%d" % (zeroize_idx, free_idx, install_idx)


@check("65. resumption handle is zeroized on final cleanup (deinit/replace-session/disconnect, via the single s_clear_session_material owner)")
def _c65():
    text = _read(APP_C)
    fn_start = text.find("static void s_clear_resumption_handle(")
    fn_end = text.find("\n}\n", fn_start)
    body = text[fn_start:fn_end]
    zeroizes = "mbedtls_platform_zeroize(ctx->resumption_handle, ctx->resumption_handle_len)" in body
    frees = "free(ctx->resumption_handle)" in body
    wired_into_clear_session_material = "s_clear_resumption_handle(ctx)" in text[text.find("static void s_clear_session_material("):]
    return zeroizes and frees and wired_into_clear_session_material, "zeroizes=%s frees=%s wired=%s" % (zeroizes, frees, wired_into_clear_session_material)


@check("66. resumption handle is NOT cleared merely because a resumable remote close occurred (CLOSED/DISCONNECTED handler never calls the clear helper)")
def _c66():
    text = _read(APP_C)
    m = re.search(r"case WEBSOCKET_EVENT_CLOSED:\s*\n\s*case WEBSOCKET_EVENT_DISCONNECTED: \{(.*?)\n    \}\n\n    default:", text, re.DOTALL)
    if not m:
        return False, "CLOSED/DISCONNECTED case block not found"
    body = m.group(1)
    return "s_clear_resumption_handle" not in body and "s_clear_session_material" not in body, "body_excerpt_len=%d" % len(body)


@check("67. app_gptnix_watcher_voice_resume_once() is never called from s_ws_event_handler")
def _c67():
    text = _read(APP_C)
    # The DEFINITION (ending in "{"), not the earlier forward declaration (ending in ";") -- both share
    # the same "static void s_ws_event_handler(" prefix, so find() alone would land on the declaration
    # (which appears first in the file) and sweep the entire rest of the file as "body", producing a
    # false positive on any later, unrelated use of the word "resume_once" (e.g. its own definition).
    def_marker = "static void s_ws_event_handler(void *handler_args,\n                                esp_event_base_t base,\n                                int32_t event_id,\n                                void *event_data)\n{"
    fn_start = text.find(def_marker)
    fn_end = text.find("\n#else /* !CONFIG_GPTNIX_WATCHER_VOICE */")
    if fn_start < 0 or fn_end < 0:
        return False, "s_ws_event_handler definition span not found"
    body = text[fn_start:fn_end]
    return "resume_once" not in body, "resume_once found inside s_ws_event_handler definition span"


@check("68. app_gptnix_watcher_voice_resume_once has exactly one call site (its own definition) anywhere in this milestone's modified/read firmware sources")
def _c68():
    text_c = _read(APP_C)
    def_sites = len(re.findall(r"app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_resume_once\(void\)\n\{", text_c))
    # A C call site to a void-argument function never repeats "void" (e.g. "= foo();"), so this pattern
    # structurally cannot overlap with a def_sites match ("...resume_once(void)\n{") -- no subtraction
    # needed, this count is already call-sites-only.
    call_sites_in_c = len(re.findall(r"\bapp_gptnix_watcher_voice_resume_once\(\)", text_c))
    runtime_c_path = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_voice_runtime.c")
    runtime_text = _read(runtime_c_path)
    runtime_refs = runtime_text.count("resume_once")
    # Two definitions expected (real + disabled-config stub); zero call sites of the symbol anywhere in
    # this file or in the runtime bridge module -- never called automatically in this milestone.
    return def_sites == 2 and call_sites_in_c == 0 and runtime_refs == 0, "def_sites=%d call_sites_in_c=%d runtime_refs=%d" % (def_sites, call_sites_in_c, runtime_refs)


@check("69. resume_once() preconditions require resumption_configured, resumption_available, state==CLOSED, and a non-NULL ws_client before any mutation")
def _c69():
    text = _read(APP_C)
    fn_start = text.find("app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_resume_once(void)\n{")
    fn_end = text.find("\napp_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_send_audio", fn_start)
    body = text[fn_start:fn_end]
    required = [
        "!ctx->resumption_configured",
        "!ctx->resumption_available",
        "ctx->state != GPTNIX_WATCHER_VOICE_STATE_CLOSED",
        "ctx->ws_client == NULL",
    ]
    missing = [s for s in required if s not in body]
    return not missing, "missing=%s" % missing


@check("70. resume_once() never creates a second esp_websocket_client_init instance -- exactly one call site in the whole file, inside connect() only")
def _c70():
    text = _read(APP_C)
    init_sites = len(re.findall(r"esp_websocket_client_init\(", text))
    fn_start = text.find("app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_resume_once(void)\n{")
    fn_end = text.find("\napp_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_send_audio", fn_start)
    resume_body = text[fn_start:fn_end]
    return init_sites == 1 and "esp_websocket_client_init(" not in resume_body, "init_sites=%d" % init_sites


@check("71. resume_once() never references the module-owned ephemeral token (no retention added)")
def _c71():
    text = _read(APP_C)
    fn_start = text.find("app_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_resume_once(void)\n{")
    fn_end = text.find("\napp_gptnix_watcher_voice_result_t app_gptnix_watcher_voice_send_audio", fn_start)
    resume_body = text[fn_start:fn_end]
    return "ctx->token" not in resume_body, "ctx->token referenced inside resume_once()"


@check("72. disable_auto_reconnect remains exactly one assignment, unchanged, only inside connect()")
def _c72():
    text = _read(APP_C)
    sites = len(re.findall(r"config\.disable_auto_reconnect = true;", text))
    other_values = len(re.findall(r"disable_auto_reconnect\s*=\s*false", text))
    return sites == 1 and other_values == 0, "sites=%d other_values=%d" % (sites, other_values)


@check("73. app_gptnix_watcher_voice.c never #includes the M3C audio runtime bridge header or calls its/the driver-layer functions")
def _c73():
    text = _read(APP_C)
    # A plain-English comment naming a sibling file for architectural context (e.g. the pre-existing
    # "registered by an external module (app_gptnix_watcher_voice_runtime.c)" docstring) is expected,
    # legitimate documentation, not a violation -- only an actual #include directive or a real call-shaped
    # reference (name immediately followed by an open paren) to these driver-layer symbols would be.
    include_hit = re.search(r'#include\s*"app_gptnix_watcher_voice_runtime\.h"', text) is not None
    call_forbidden = ["s_audio_capture_task", "s_audio_send_task", "app_audio_recorder_", "app_audio_player_"]
    call_hits = [s for s in call_forbidden if re.search(re.escape(s) + r"\w*\(", text)]
    return (not include_hit) and (not call_hits), "include_hit=%s call_hits=%s" % (include_hit, call_hits)


@check("74. app_gptnix_watcher_voice.c never creates a FreeRTOS task")
def _c74():
    text = _read(APP_C)
    hits = len(re.findall(r"\bxTaskCreate\w*\(", text))
    return hits == 0, "xTaskCreate call count=%d" % hits


@check("75. app_gptnix_watcher_voice.c never references resampler/sample-rate symbols owned by the runtime bridge")
def _c75():
    text = _read(APP_C)
    forbidden = ["s_resample_24k_to_16k", "GW_AUDIO_OUT_SAMPLE_RATE", "s_resample_prev", "s_resample_pos"]
    hits = [s for s in forbidden if s in text]
    return not hits, "hits=%s" % hits


FITNESS_CHECK_COUNT = 75


def main():
    print("=== GPTNiX Watcher voice foundation fitness test (M2) ===")
    print("FACTORY_DIR=%s" % FACTORY_DIR)
    print("BASE_SHA=%s" % BASE_SHA)
    if FAILURES:
        print("\n%d invariant(s) FAILED: %s" % (len(FAILURES), FAILURES))
        return 1
    print("\nAll invariants PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
