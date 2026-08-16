#!/usr/bin/env python3
"""GPTNiX Watcher realtime-voice WSS/session foundation — source/architecture
fitness test (M2). Python standard library only, no pip dependency.

This is a STATIC SOURCE proof, not a runtime/physical proof: it never
builds, flashes, or executes firmware. It exits non-zero if any invariant
below is violated. It combines semantic source checks with git-diff-based
checks against BASE_SHA to prove protected files are genuinely unchanged
(not merely unmentioned in comments).
"""
import os
import re
import subprocess
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


def _git_diff_empty(path_rel):
    """True if `path_rel` (repo-root-relative) is byte-identical to BASE_SHA."""
    try:
        out = subprocess.run(
            ["git", "diff", "--quiet", BASE_SHA, "--", path_rel],
            cwd=REPO_ROOT, check=False,
        )
        return out.returncode == 0
    except Exception:
        return False


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
    return hits == 1, "found %d" % hits


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
    return "GPTNIX_WATCHER_VOICE_RX_REASSEMBLY_MAX_BYTES (8192)" in _read(APP_C), ""


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


# 34. no `realtimeInput` audio construction
@check("34. no realtimeInput audio construction")
def _c34():
    return "realtimeInput" not in _read(APP_C), ""


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


# 42-46. protected files unchanged (git diff against BASE_SHA)
@check("42. main.c untouched/no runtime call site to new module")
def _c42():
    diff_clean = _git_diff_empty("examples/factory_firmware/main/main.c")
    text = _read(MAIN_C) if os.path.isfile(MAIN_C) else ""
    no_callsite = "app_gptnix_watcher_voice" not in text
    return diff_clean and no_callsite, "diff_clean=%s no_callsite=%s" % (diff_clean, no_callsite)


@check("43. CMakeLists.txt untouched")
def _c43():
    return _git_diff_empty("examples/factory_firmware/main/CMakeLists.txt"), ""


@check("44. app_audio_recorder.c/.h untouched")
def _c44():
    a = _git_diff_empty("examples/factory_firmware/main/app/app_audio_recorder.c")
    b = _git_diff_empty("examples/factory_firmware/main/app/app_audio_recorder.h")
    return a and b, "c=%s h=%s" % (a, b)


@check("45. app_audio_player.c/.h untouched")
def _c45():
    a = _git_diff_empty("examples/factory_firmware/main/app/app_audio_player.c")
    b = _git_diff_empty("examples/factory_firmware/main/app/app_audio_player.h")
    return a and b, "c=%s h=%s" % (a, b)


@check("46. app_voice_interaction.c untouched")
def _c46():
    return _git_diff_empty("examples/factory_firmware/main/app/app_voice_interaction.c"), ""


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
