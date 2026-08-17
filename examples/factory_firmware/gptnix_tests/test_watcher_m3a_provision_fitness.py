#!/usr/bin/env python3
"""GPTNiX Watcher M3A host-controlled provisioning canary -- source/architecture
fitness test. Python standard library only, no pip dependency.

This is a STATIC SOURCE proof, not a runtime/physical proof: it never builds,
flashes, or executes firmware, never opens a serial port, never starts SSH,
and never makes a network call. It exits non-zero if any invariant below is
violated. Blob-identity checks against app_gptnix_watcher_voice.c/.h and
app_wifi.c/.h use the SAME shallow-clone-safe, no-BASE_SHA-dereference
technique already established by test_watcher_voice_fitness.py's
PROTECTED_BASE_BLOBS (see that file's own docstring) -- the CI checkout here
also uses fetch-depth: 1.
"""
import hashlib
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FACTORY_DIR = os.path.dirname(SCRIPT_DIR)  # .../examples/factory_firmware
REPO_ROOT = os.path.dirname(os.path.dirname(FACTORY_DIR))  # repo root

PROVISION_C = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_provision.c")
PROVISION_H = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_provision.h")
APP_CMD_C = os.path.join(FACTORY_DIR, "main", "app", "app_cmd.c")
APP_CMD_H = os.path.join(FACTORY_DIR, "main", "app", "app_cmd.h")
MAIN_C = os.path.join(FACTORY_DIR, "main", "main.c")
KCONFIG = os.path.join(FACTORY_DIR, "main", "Kconfig.projbuild")
BRIDGE_PS1 = os.path.join(FACTORY_DIR, "tools", "gptnix_watcher_m3a_bridge.ps1")
WORKFLOW_YML = os.path.join(REPO_ROOT, ".github", "workflows", "gptnix-firmware-build.yml")

# Immutable Git blob IDs of files this milestone must NOT touch, captured out-of-band the same way
# test_watcher_voice_fitness.py's PROTECTED_BASE_BLOBS were (git hash-object --no-filters <path>), cross-
# checked against the current worktree before being embedded here. Never dereferences BASE_SHA/history at
# runtime -- CI uses fetch-depth: 1.
PROTECTED_M3A_BLOBS = {
    "examples/factory_firmware/main/app/app_gptnix_watcher_voice.c":
        "c20f9d1934879a8b645aa462e15de49304cd7329",
    "examples/factory_firmware/main/app/app_gptnix_watcher_voice.h":
        "85399fa916407ab9d8602b62d8a7cc6946b5ec40",
    "examples/factory_firmware/main/app/app_wifi.c":
        "96f3e1a240c70c3500f977d59c9aea7ed51b1077",
    "examples/factory_firmware/main/app/app_wifi.h":
        "a05d78e0e0fe69708cc99e3253d1dbbd5547d4f7",
}

FAILURES = []
CHECK_COUNT = [0]


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def check(name):
    def decorator(fn):
        CHECK_COUNT[0] += 1
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


def _working_tree_git_blob_sha(path_rel):
    abs_path = os.path.join(REPO_ROOT, path_rel)
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def _protected_matches(path_rel):
    expected = PROTECTED_M3A_BLOBS.get(path_rel)
    if expected is None:
        return False
    return _working_tree_git_blob_sha(path_rel) == expected


def _strip_c_comments(text):
    """Single-pass scanner: strips // and /* */ comments while correctly skipping over "..." and '...'
    literals (including escaped quotes), so a "//" inside a string -- e.g. "https://" -- is never mistaken
    for a line-comment start. A naive two-pass regex stripper gets this wrong."""
    out = []
    i, n = 0, len(text)
    state = None  # None | 'line_comment' | 'block_comment' | 'string' | 'char'
    while i < n:
        c = text[i]
        c2 = text[i + 1] if i + 1 < n else ""
        if state == "line_comment":
            if c == "\n":
                state = None
                out.append(c)
            i += 1
            continue
        if state == "block_comment":
            if c == "*" and c2 == "/":
                state = None
                i += 2
                continue
            i += 1
            continue
        if state in ("string", "char"):
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if (state == "string" and c == '"') or (state == "char" and c == "'"):
                state = None
            i += 1
            continue
        # not inside any special state
        if c == "/" and c2 == "/":
            state = "line_comment"
            i += 2
            continue
        if c == "/" and c2 == "*":
            state = "block_comment"
            i += 2
            continue
        if c == '"':
            state = "string"
            out.append(c)
            i += 1
            continue
        if c == "'":
            state = "char"
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _extract_c_function(text, signature_marker, next_marker=None):
    """Returns the substring of `text` from `signature_marker` to `next_marker` (or end of file). Used to scope
    a structural check to one function's body without a full C parser."""
    start = text.find(signature_marker)
    if start == -1:
        return ""
    if next_marker is None:
        return text[start:]
    end = text.find(next_marker, start + len(signature_marker))
    return text[start:] if end == -1 else text[start:end]


PROVISION_C_RAW = _read(PROVISION_C) if os.path.isfile(PROVISION_C) else ""
PROVISION_C_CODE = _strip_c_comments(PROVISION_C_RAW)
PROVISION_H_RAW = _read(PROVISION_H) if os.path.isfile(PROVISION_H) else ""
APP_CMD_C_RAW = _read(APP_CMD_C)
APP_CMD_C_CODE = _strip_c_comments(APP_CMD_C_RAW)
APP_CMD_H_RAW = _read(APP_CMD_H)
MAIN_C_RAW = _read(MAIN_C)
MAIN_C_CODE = _strip_c_comments(MAIN_C_RAW)
KCONFIG_RAW = _read(KCONFIG)
BRIDGE_PS1_RAW = _read(BRIDGE_PS1) if os.path.isfile(BRIDGE_PS1) else ""
WORKFLOW_RAW = _read(WORKFLOW_YML) if os.path.isfile(WORKFLOW_YML) else ""


def main():
    print("=== GPTNiX Watcher M3A provisioning canary fitness test ===")
    print("FACTORY_DIR=%s" % FACTORY_DIR)
    if FAILURES:
        print("\n%d invariant(s) FAILED: %s" % (len(FAILURES), FAILURES))
        return 1
    print("\nAll %d invariants PASS." % CHECK_COUNT[0])
    return 0


# ===========================================================================
# Protocol (1-7)
# ===========================================================================

@check("1. protocol magic GNX3")
def _c1():
    c_ok = "'G'" in PROVISION_C_CODE and "'N'" in PROVISION_C_CODE and "'X'" in PROVISION_C_CODE and "'3'" in PROVISION_C_CODE
    ps_ok = "0x47, 0x4E, 0x58, 0x33" in BRIDGE_PS1_RAW
    return c_ok and ps_ok, "c_ok=%s ps_ok=%s" % (c_ok, ps_ok)


@check("2. version 1")
def _c2():
    c_ok = bool(re.search(r"GW_M3A_VERSION\s+0x01", PROVISION_C_CODE))
    ps_ok = "GwVersion" in BRIDGE_PS1_RAW and "0x01" in BRIDGE_PS1_RAW
    return c_ok and ps_ok, "c_ok=%s ps_ok=%s" % (c_ok, ps_ok)


@check("3. header 8")
def _c3():
    c_ok = bool(re.search(r"GW_M3A_HEADER_BYTES\s+8\b", PROVISION_C_CODE))
    ps_ok = bool(re.search(r"GwHeaderBytes\s*=\s*8\b", BRIDGE_PS1_RAW))
    return c_ok and ps_ok, "c_ok=%s ps_ok=%s" % (c_ok, ps_ok)


@check("4. max payload 4096")
def _c4():
    c_ok = "GW_M3A_MAX_PAYLOAD_BYTES 4096" in PROVISION_C_CODE
    ps_ok = bool(re.search(r"GwMaxPayloadBytes\s*=\s*4096\b", BRIDGE_PS1_RAW))
    return c_ok and ps_ok, "c_ok=%s ps_ok=%s" % (c_ok, ps_ok)


@check("5. exact five message types")
def _c5():
    c_types = {
        "GW_M3A_MSG_BRIDGE_READY": "0x01", "GW_M3A_MSG_TOKEN_FRAME": "0x02", "GW_M3A_MSG_TOKEN_STAGED": "0x03",
        "GW_M3A_MSG_PROVISION_COMMIT": "0x04", "GW_M3A_MSG_PROVISION_ABORT": "0x05",
    }
    c_missing = [k for k, v in c_types.items() if not re.search(r"%s\s+%s\b" % (re.escape(k), re.escape(v)), PROVISION_C_CODE)]
    ps_types = {
        "GwMsgBridgeReady": "0x01", "GwMsgTokenFrame": "0x02", "GwMsgTokenStaged": "0x03",
        "GwMsgProvisionCommit": "0x04", "GwMsgProvisionAbort": "0x05",
    }
    ps_missing = [k for k, v in ps_types.items() if not re.search(r"%s\s*=\s*\[byte\]%s\b" % (re.escape(k), re.escape(v)), BRIDGE_PS1_RAW)]
    return not c_missing and not ps_missing, "c_missing=%s ps_missing=%s" % (c_missing, ps_missing)


@check("6. zero-payload control types enforced")
def _c6():
    return "hdr.payload_len != 0" in PROVISION_C_CODE, ""


@check("7. TOKEN_FRAME bound 1..4096")
def _c7():
    return "hdr.payload_len < 1 || hdr.payload_len > GW_M3A_MAX_PAYLOAD_BYTES" in PROVISION_C_CODE, ""


# ===========================================================================
# Kconfig (8-13)
# ===========================================================================

@check("8. GPTNIX_WATCHER_PROVISION exists exactly once")
def _c8():
    n = len(re.findall(r"^\s*config\s+GPTNIX_WATCHER_PROVISION\s*$", KCONFIG_RAW, re.MULTILINE))
    return n == 1, "found %d" % n


@check("9. GPTNIX_WATCHER_PROVISION default n")
def _c9():
    m = re.search(r"config\s+GPTNIX_WATCHER_PROVISION\s*\n(.*?)(?=\n\s*config\s|\Z)", KCONFIG_RAW, re.DOTALL)
    return bool(m and re.search(r"^\s*default\s+n\s*$", m.group(1), re.MULTILINE)), ""


@check("10. GPTNIX_WATCHER_PROVISION depends on GPTNIX_WATCHER_VOICE")
def _c10():
    m = re.search(r"config\s+GPTNIX_WATCHER_PROVISION\s*\n(.*?)(?=\n\s*config\s|\Z)", KCONFIG_RAW, re.DOTALL)
    return bool(m and re.search(r"^\s*depends on\s+GPTNIX_WATCHER_VOICE\s*$", m.group(1), re.MULTILINE)), ""


@check("11. GPTNIX_WATCHER_SESSION_URL exists exactly once")
def _c11():
    n = len(re.findall(r"^\s*config\s+GPTNIX_WATCHER_SESSION_URL\s*$", KCONFIG_RAW, re.MULTILINE))
    return n == 1, "found %d" % n


@check("12. GPTNIX_WATCHER_SESSION_URL default empty")
def _c12():
    m = re.search(r"config\s+GPTNIX_WATCHER_SESSION_URL\s*\n(.*?)(?=\n\s*config\s|\nendmenu)", KCONFIG_RAW, re.DOTALL)
    return bool(m and re.search(r'^\s*default\s+""\s*$', m.group(1), re.MULTILINE)), ""


@check("13. GPTNIX_WATCHER_SESSION_URL depends on GPTNIX_WATCHER_PROVISION")
def _c13():
    m = re.search(r"config\s+GPTNIX_WATCHER_SESSION_URL\s*\n(.*?)(?=\n\s*config\s|\nendmenu)", KCONFIG_RAW, re.DOTALL)
    return bool(m and re.search(r"^\s*depends on\s+GPTNIX_WATCHER_PROVISION\s*$", m.group(1), re.MULTILINE)), ""


# ===========================================================================
# Console split (14-22)
# ===========================================================================

@check("14. app_cmd_prepare_repl declared + defined")
def _c14():
    declared = "int app_cmd_prepare_repl(void);" in APP_CMD_H_RAW
    defined = bool(re.search(r"\bint\s+app_cmd_prepare_repl\s*\(void\)\s*\n\{", APP_CMD_C_CODE))
    return declared and defined, "declared=%s defined=%s" % (declared, defined)


@check("15. app_cmd_start_repl declared + defined")
def _c15():
    declared = "int app_cmd_start_repl(void);" in APP_CMD_H_RAW
    defined = bool(re.search(r"\bint\s+app_cmd_start_repl\s*\(void\)\s*\n\{", APP_CMD_C_CODE))
    return declared and defined, "declared=%s defined=%s" % (declared, defined)


@check("16. app_cmd_init compatibility wrapper retained")
def _c16():
    declared = "int app_cmd_init(void);" in APP_CMD_H_RAW
    body = _extract_c_function(APP_CMD_C_CODE, "int app_cmd_init(void)")
    calls_both = "app_cmd_prepare_repl()" in body and "app_cmd_start_repl()" in body
    return declared and calls_both, "declared=%s calls_both=%s" % (declared, calls_both)


@check("17. esp_console_new_repl_* branches owned solely by app_cmd_prepare_repl")
def _c17():
    prepare_body = _extract_c_function(APP_CMD_C_CODE, "int app_cmd_prepare_repl(void)", "int app_cmd_start_repl(void)")
    in_prepare = len(re.findall(r"esp_console_new_repl_\w+\(", prepare_body))
    outside = APP_CMD_C_CODE.replace(prepare_body, "")
    out_count = len(re.findall(r"esp_console_new_repl_\w+\(", outside))
    return in_prepare >= 1 and out_count == 0, "in_prepare=%d outside=%d" % (in_prepare, out_count)


@check("18. exactly one esp_console_start_repl call site")
def _c18():
    n = len(re.findall(r"esp_console_start_repl\(", APP_CMD_C_CODE))
    return n == 1, "found %d" % n


@check("19. no second uart_driver_install in app_cmd.c")
def _c19():
    n = len(re.findall(r"uart_driver_install\(", APP_CMD_C_CODE))
    return n == 0, "found %d" % n


@check("20. provision module uses CONFIG_ESP_CONSOLE_UART_NUM")
def _c20():
    return "CONFIG_ESP_CONSOLE_UART_NUM" in PROVISION_C_CODE, ""


@check("21. provision module uses uart_read_bytes")
def _c21():
    return bool(re.search(r"\buart_read_bytes\(", PROVISION_C_CODE)), ""


@check("22. provision module never uses linenoise/scanf/fgets/argv")
def _c22():
    hits = [s for s in ("linenoise(", "scanf(", "fgets(", "argv") if s in PROVISION_C_CODE]
    return not hits, "found: %s" % hits


# ===========================================================================
# Main callsite (23-27)
# ===========================================================================

@check("23. exactly one app_gptnix_watcher_provision_run call in main.c")
def _c23():
    n = len(re.findall(r"app_gptnix_watcher_provision_run\(\)", MAIN_C_CODE))
    return n == 1, "found %d" % n


@check("24. call is compile-gated by CONFIG_GPTNIX_WATCHER_PROVISION")
def _c24():
    m = re.search(r"#if\s+CONFIG_GPTNIX_WATCHER_PROVISION(.*?)#else", MAIN_C_RAW, re.DOTALL)
    return bool(m and "app_gptnix_watcher_provision_run()" in m.group(1)), ""


@check("25. OFF branch retains app_cmd_init()")
def _c25():
    m = re.search(r"#else(.*?)#endif", MAIN_C_RAW, re.DOTALL)
    return bool(m and "app_cmd_init();" in m.group(1)), ""


@check("26. main.c has zero direct calls into the M2 realtime-voice API")
def _c26():
    n = len(re.findall(r"app_gptnix_watcher_voice", MAIN_C_CODE))
    return n == 0, "found %d" % n


@check("27. app_sensor_init() remains after the console/provision block")
def _c27():
    idx_endif = MAIN_C_RAW.find("#endif")
    idx_sensor = MAIN_C_RAW.find("app_sensor_init();")
    return idx_endif != -1 and idx_sensor != -1 and idx_endif < idx_sensor, ""


# ===========================================================================
# Secret / device identity (28-38)
# ===========================================================================

@check("28. no nvs_set/nvs_open/nvs_commit in provision module")
def _c28():
    hits = [s for s in ("nvs_set", "nvs_open", "nvs_commit") if s in PROVISION_C_CODE]
    return not hits, "found: %s" % hits


@check("29. no identitytoolkit reference")
def _c29():
    return "identitytoolkit" not in PROVISION_C_CODE.lower(), ""


@check("30. no securetoken reference")
def _c30():
    return "securetoken" not in PROVISION_C_CODE.lower(), ""


@check("31. no Firebase Web API key symbol")
def _c31():
    hits = [s for s in ("FIREBASE_WEB_API", "FIREBASE_API_KEY", "firebaseApiKey") if s in PROVISION_C_CODE]
    return not hits, "found: %s" % hits


@check("32. no pairing endpoint literal")
def _c32():
    return "/v2/watcher/pairing" not in PROVISION_C_CODE, ""


@check("33. no refresh token field/string")
def _c33():
    hits = [s for s in ("refresh_token", "refreshToken", "REFRESH_TOKEN") if s in PROVISION_C_CODE]
    return not hits, "found: %s" % hits


@check("34. no custom token field/string")
def _c34():
    hits = [s for s in ("custom_token", "customToken", "CUSTOM_TOKEN") if s in PROVISION_C_CODE]
    return not hits, "found: %s" % hits


@check("35. no token log format (%s in an ESP_LOG line)")
def _c35():
    offending = [ln for ln in PROVISION_C_RAW.splitlines() if "ESP_LOG" in ln and "%s" in ln]
    return not offending, "lines: %s" % offending


@check("36. ID token buffer zeroization")
def _c36():
    return "mbedtls_platform_zeroize(token_buf" in PROVISION_C_CODE, ""


@check("37. Authorization buffer zeroization")
def _c37():
    return "mbedtls_platform_zeroize(auth_value" in PROVISION_C_CODE, ""


@check("38. session response buffer zeroization")
def _c38():
    hits = ("mbedtls_platform_zeroize(acc.buf" in PROVISION_C_CODE) and ("mbedtls_platform_zeroize(response_buf" in PROVISION_C_CODE)
    return hits, ""


# ===========================================================================
# Commit state machine (39-44)
# ===========================================================================

@check("39. TOKEN_STAGED emitted only after the token is staged")
def _c39():
    run_body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_run_provision_cycle(void)")
    idx_recv = run_body.find("s_receive_token_frame(")
    idx_staged = run_body.find("GW_M3A_MSG_TOKEN_STAGED")
    return idx_recv != -1 and idx_staged != -1 and idx_recv < idx_staged, ""


@check("40. HTTP session function unreachable before the COMMIT guard")
def _c40():
    run_body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_run_provision_cycle(void)")
    idx_commit_guard = run_body.find("s_wait_for_commit_or_abort(")
    idx_post = run_body.find("s_do_session_post(")
    return idx_commit_guard != -1 and idx_post != -1 and idx_commit_guard < idx_post, ""


@check("41. ABORT / commit-timeout / malformed-commit all zeroize the token (zero session POSTs)")
def _c41():
    run_body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_run_provision_cycle(void)")
    idx_commit_call = run_body.find("s_wait_for_commit_or_abort(")
    idx_ip_wait = run_body.find("s_wait_for_ip(")
    between = run_body[idx_commit_call:idx_ip_wait] if idx_commit_call != -1 and idx_ip_wait != -1 else ""
    return "mbedtls_platform_zeroize(token_buf" in between and "free(token_buf)" in between, ""


@check("42. commit-wait classifies ABORT/timeout/malformed distinctly (no silent success)")
def _c42():
    body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_wait_for_commit_or_abort", "static bool s_session_url_valid")
    has = ("GPTNIX_WATCHER_PROVISION_RESULT_ABORTED" in body
        and "GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_TIMEOUT" in body
        and "GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR" in body)
    return has, ""


@check("43. malformed post-staged frame is classified, never silently accepted as COMMIT")
def _c43():
    body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_wait_for_commit_or_abort", "static bool s_session_url_valid")
    return "return GPTNIX_WATCHER_PROVISION_RESULT_TRANSPORT_PROTOCOL_ERROR;" in body, ""


@check("44. no automatic retry (single call sites, no retry loop)")
def _c44():
    perform_count = len(re.findall(r"esp_http_client_perform\(", PROVISION_C_CODE))
    post_count = len(re.findall(r"s_do_session_post\(", PROVISION_C_CODE))
    # exactly one function definition + exactly one call site
    return perform_count == 1 and post_count == 2, "perform=%d post_refs=%d" % (perform_count, post_count)


# ===========================================================================
# HTTPS (45-55)
# ===========================================================================

@check("45. session URL must be https://")
def _c45():
    return 'strncmp(url, "https://", 8)' in PROVISION_C_CODE, ""


@check("46. canonical path suffix required")
def _c46():
    return '"/v2/watcher/realtime/session"' in PROVISION_C_CODE, ""


@check("47. '?' rejected in session URL")
def _c47():
    return "c == '?'" in PROVISION_C_CODE, ""


@check("48. '#' rejected in session URL")
def _c48():
    return "c == '#'" in PROVISION_C_CODE, ""


@check("49. esp_crt_bundle_attach used")
def _c49():
    return "esp_crt_bundle_attach" in PROVISION_C_CODE, ""


@check("50. exactly one esp_http_client_perform call site")
def _c50():
    n = len(re.findall(r"esp_http_client_perform\(", PROVISION_C_CODE))
    return n == 1, "found %d" % n


@check("51. HTTP timeout 10000ms")
def _c51():
    return "GW_HTTP_TIMEOUT_MS       10000" in PROVISION_C_CODE, ""


@check("52. no redirect credential forwarding (auto-redirect disabled)")
def _c52():
    return "config.disable_auto_redirect = true;" in PROVISION_C_CODE, ""


@check("53. response bound 65536")
def _c53():
    return "GW_SESSION_RESPONSE_MAX_BYTES 65536" in PROVISION_C_CODE, ""


@check("54. pre-copy response bound check before memcpy")
def _c54():
    body = _extract_c_function(PROVISION_C_CODE, "static esp_err_t s_http_event_handler", "static app_gptnix_watcher_provision_result_t s_do_session_post")
    idx_check = body.find("acc->len + (size_t)evt->data_len > acc->cap")
    idx_copy = body.find("memcpy(acc->buf")
    return idx_check != -1 and idx_copy != -1 and idx_check < idx_copy, ""


@check("55. HTTP response body never logged")
def _c55():
    offending = [ln for ln in PROVISION_C_RAW.splitlines() if "ESP_LOG" in ln and ("evt->data" in ln or "acc.buf" in ln or "response_buf" in ln)]
    return not offending, "lines: %s" % offending


# ===========================================================================
# M2 ownership (56-66)
# ===========================================================================

@check("56. app_gptnix_watcher_voice.c untouched by this PR")
def _c56():
    return _protected_matches("examples/factory_firmware/main/app/app_gptnix_watcher_voice.c"), ""


@check("57. app_gptnix_watcher_voice.h untouched by this PR")
def _c57():
    return _protected_matches("examples/factory_firmware/main/app/app_gptnix_watcher_voice.h"), ""


@check("58. provision module has zero esp_websocket_client_* calls")
def _c58():
    n = len(re.findall(r"esp_websocket_client_\w+\(", PROVISION_C_CODE))
    return n == 0, "found %d" % n


@check("59. exactly one prepare_session call site in the provision module")
def _c59():
    n = len(re.findall(r"app_gptnix_watcher_voice_prepare_session\(", PROVISION_C_CODE))
    return n == 1, "found %d" % n


@check("60. exactly one connect call site in the provision module")
def _c60():
    n = len(re.findall(r"app_gptnix_watcher_voice_connect\(\)", PROVISION_C_CODE))
    return n == 1, "found %d" % n


@check("61. get_state polled only within a bounded READY wait")
def _c61():
    body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_hand_off_to_voice")
    has_deadline = "xTaskGetTickCount() >= deadline" in body
    has_get_state = "app_gptnix_watcher_voice_get_state()" in body
    return has_deadline and has_get_state, ""


@check("62. disconnect()/deinit() terminal cleanup present")
def _c62():
    body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_hand_off_to_voice")
    return "app_gptnix_watcher_voice_disconnect();" in body and "app_gptnix_watcher_voice_deinit();" in body, ""


@check("63. no reconnect / no retry around connect()")
def _c63():
    n = len(re.findall(r"app_gptnix_watcher_voice_connect\(\)", PROVISION_C_CODE))
    return n == 1, "connect call sites=%d" % n


@check("64. no microphone/recorder API reference in provision module")
def _c64():
    hits = [s for s in ("app_audio_recorder", "microphone") if s.lower() in PROVISION_C_CODE.lower()]
    return not hits, "found: %s" % hits


@check("65. no speaker/player API reference in provision module")
def _c65():
    hits = [s for s in ("app_audio_player", "speaker") if s.lower() in PROVISION_C_CODE.lower()]
    return not hits, "found: %s" % hits


@check("66. no realtimeInput reference in provision module")
def _c66():
    return "realtimeInput" not in PROVISION_C_CODE, ""


# ===========================================================================
# Memory / logs (67-70)
# ===========================================================================

@check("67. secret/response buffers are heap-allocated, never fixed stack arrays")
def _c67():
    token_heap = "heap_caps_malloc((size_t)hdr.payload_len + 1, MALLOC_CAP_SPIRAM)" in PROVISION_C_CODE
    auth_heap = "heap_caps_malloc(auth_len + 1, MALLOC_CAP_SPIRAM)" in PROVISION_C_CODE
    resp_heap = "heap_caps_malloc(acc.cap + 1, MALLOC_CAP_SPIRAM)" in PROVISION_C_CODE
    return token_heap and auth_heap and resp_heap, "token=%s auth=%s resp=%s" % (token_heap, auth_heap, resp_heap)


@check("68. PSRAM allocation capability used")
def _c68():
    n = len(re.findall(r"MALLOC_CAP_SPIRAM", PROVISION_C_CODE))
    return n >= 3, "found %d" % n


@check("69. heap stage logs are numeric only")
def _c69():
    heap_lines = [ln for ln in PROVISION_C_RAW.splitlines() if "heap: stage=" in ln]
    bad = [ln for ln in heap_lines if "%s" in ln]
    return bool(heap_lines) and not bad, "heap_lines=%d bad=%s" % (len(heap_lines), bad)


@check("70. no %s secret log anywhere in the provision module")
def _c70():
    offending = [ln for ln in PROVISION_C_RAW.splitlines() if "ESP_LOG" in ln and "%s" in ln]
    return not offending, "lines: %s" % offending


# ===========================================================================
# Bridge (71-89)
# ===========================================================================

@check("71. bridge file exists")
def _c71():
    return os.path.isfile(BRIDGE_PS1), ""


@check("72. no secret parameter names in the bridge param() block")
def _c72():
    m = re.search(r"param\((.*?)\)\s*\n", BRIDGE_PS1_RAW, re.DOTALL)
    block = m.group(1) if m else ""
    hits = [s for s in ("$Token", "$IdToken", "$RefreshToken", "$PairingValue", "$ApiKey", "$Password") if s in block]
    return not hits, "found: %s" % hits


@check("73. uses System.IO.Ports.SerialPort")
def _c73():
    return "System.IO.Ports.SerialPort" in BRIDGE_PS1_RAW, ""


@check("74. DTR disabled")
def _c74():
    return "$port.DtrEnable = $false" in BRIDGE_PS1_RAW, ""


@check("75. RTS disabled")
def _c75():
    return "$port.RtsEnable = $false" in BRIDGE_PS1_RAW, ""


@check("76. uses System.Diagnostics.Process")
def _c76():
    return "System.Diagnostics.Process" in BRIDGE_PS1_RAW, ""


@check("77. UseShellExecute is false")
def _c77():
    return "$psi.UseShellExecute = $false" in BRIDGE_PS1_RAW, ""


@check("78. RedirectStandardInput is true")
def _c78():
    return "$psi.RedirectStandardInput = $true" in BRIDGE_PS1_RAW, ""


@check("79. RedirectStandardOutput is true")
def _c79():
    return "$psi.RedirectStandardOutput = $true" in BRIDGE_PS1_RAW, ""


@check("80. ssh.exe invoked with -T (no PTY)")
def _c80():
    return "'ssh.exe'" in BRIDGE_PS1_RAW and '"-T $SshTarget' in BRIDGE_PS1_RAW, ""


@check("81. remote fd mapping is exactly 3>&1 1>&2")
def _c81():
    return "3>&1 1>&2" in BRIDGE_PS1_RAW, ""


@check("82. device BRIDGE_READY precedes starting the backend process")
def _c82():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    idx_wait = body.find("Wait-GwBridgeReady")
    idx_start = body.find("Start-GwBackendProcess")
    return idx_wait != -1 and idx_start != -1 and idx_wait < idx_start, ""


@check("83. raw serial/noise bytes are never printed")
def _c83():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    offending = [ln for ln in live_body.splitlines() if re.search(r"Write-(Host|Output)\s+\$b\b", ln)]
    return not offending, "lines: %s" % offending


@check("84. TOKEN_FRAME payload is never converted to a String")
def _c84():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    hits = [s for s in ("GetString(", "[string]$payload", "[string]$frame") if s in body]
    return not hits, "found: %s" % hits


@check("85. token-bearing byte[] cleared after use")
def _c85():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    return "[Array]::Clear($frame" in body and "[Array]::Clear($payload" in body, ""


@check("86. TOKEN_STAGED forwarded upstream only after a real device TOKEN_STAGED")
def _c86():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    idx_confirm = live_body.find("Confirm-GwDeviceTokenStaged")
    idx_forward = live_body.find("$stagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged")
    return idx_confirm != -1 and idx_forward != -1 and idx_confirm < idx_forward, ""


@check("87. bridge cannot originate PROVISION_ABORT after forwarding TOKEN_STAGED")
def _c87():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    idx_forward = live_body.find("$stagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged")
    after = live_body[idx_forward:] if idx_forward != -1 else live_body
    return "New-GwFrame -Type $Script:GwMsgProvisionAbort" not in after, ""


@check("88. no temp file token path")
def _c88():
    hits = [s for s in ("Out-File", "Set-Content", "[System.IO.File]::Write") if s in BRIDGE_PS1_RAW]
    return not hits, "found: %s" % hits


@check("89. -SelfTest exists and drives Invoke-GwSelfTest")
def _c89():
    return "[switch]$SelfTest" in BRIDGE_PS1_RAW and "Invoke-GwSelfTest" in BRIDGE_PS1_RAW, ""


@check("89b. -SelfTest never opens serial / starts SSH / touches the network")
def _c89b():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwSelfTest")
    hits = [s for s in ("SerialPort", "Process]::Start", "Start-GwBackendProcess", "Invoke-WebRequest", "Invoke-RestMethod") if s in body]
    return not hits, "found: %s" % hits


# ===========================================================================
# Workflow (90-100)
# ===========================================================================

@check("90. PR trigger is still baseline/fw-v1.1.7")
def _c90():
    return bool(re.search(r"branches:\s*\n\s*-\s*baseline/fw-v1\.1\.7", WORKFLOW_RAW)), ""


@check("91. IDF v5.2.1 pinned")
def _c91():
    n = len(re.findall(r"esp_idf_version:\s*v5\.2\.1", WORKFLOW_RAW))
    return n >= 3, "found %d" % n


@check("92. target esp32s3")
def _c92():
    n = len(re.findall(r"target:\s*esp32s3", WORKFLOW_RAW))
    return n >= 3, "found %d" % n


@check("93. checkout action still pinned by SHA")
def _c93():
    n = len(re.findall(r"actions/checkout@11d5960a326750d5838078e36cf38b85af677262", WORKFLOW_RAW))
    return n >= 2, "found %d" % n


def _workflow_command_for_mode(mode_marker):
    m = re.search(r"mode=%s\).*?command:\s*'([^']*)'" % re.escape(mode_marker), WORKFLOW_RAW, re.DOTALL)
    return m.group(1) if m else ""


OFF_BUILD_COMMAND = _workflow_command_for_mode("off")
VOICE_BUILD_COMMAND = _workflow_command_for_mode("voice")


@check("94. OFF build step exists and actually builds (real idf.py invocation, not skipped/no-op)")
def _c94():
    return "matrix.mode == 'off'" in WORKFLOW_RAW and "idf.py -B build-gptnix-off build" in OFF_BUILD_COMMAND, ""


@check("95. voice-only build step exists and actually builds (real idf.py invocation, not skipped/no-op)")
def _c95():
    return "matrix.mode == 'voice'" in WORKFLOW_RAW and "idf.py -B build-gptnix-voice" in VOICE_BUILD_COMMAND, ""


@check("96. M3A build step sets both voice and provision ON")
def _c96():
    m = re.search(r"mode=m3a\).*?command:\s*'([^']*)'", WORKFLOW_RAW, re.DOTALL)
    cmd = m.group(1) if m else ""
    return "CONFIG_GPTNIX_WATCHER_VOICE=y" in cmd and "CONFIG_GPTNIX_WATCHER_PROVISION=y" in cmd, ""


@check("97. M3A provision fitness runs in CI")
def _c97():
    return "test_watcher_m3a_provision_fitness.py" in WORKFLOW_RAW, ""


@check("98. M2 voice fitness still runs in CI")
def _c98():
    return "test_watcher_voice_fitness.py" in WORKFLOW_RAW, ""


@check("99. Windows bridge self-test job exists")
def _c99():
    return "m3a-bridge-selftest" in WORKFLOW_RAW and "windows-2022" in WORKFLOW_RAW and "-SelfTest" in WORKFLOW_RAW, ""


@check("100. no device flash/upload step in the workflow")
def _c100():
    hits = [ln for ln in WORKFLOW_RAW.splitlines() if re.search(r"\b(flash|upload)\b", ln, re.IGNORECASE)]
    return not hits, "lines: %s" % hits


# ===========================================================================
# M3A.3B correction (CI + bridge safety) -- 101-...
# ===========================================================================

M3A_BUILD_COMMAND = _workflow_command_for_mode("m3a")

# ---- Workflow: RC1 fix (OFF/voice sdkconfig assertions valid for a Kconfig symbol hidden by depends-on) ----

@check("101. OFF assertion does not require the dependent PROVISION '# ... is not set' literal")
def _c101():
    return '# CONFIG_GPTNIX_WATCHER_PROVISION is not set' not in OFF_BUILD_COMMAND, ""


@check("102. OFF semantically proves CONFIG_GPTNIX_WATCHER_VOICE=y is absent")
def _c102():
    return '! grep -qx "CONFIG_GPTNIX_WATCHER_VOICE=y" sdkconfig' in OFF_BUILD_COMMAND, ""


@check("103. OFF semantically proves CONFIG_GPTNIX_WATCHER_PROVISION=y is absent")
def _c103():
    return '! grep -qx "CONFIG_GPTNIX_WATCHER_PROVISION=y" sdkconfig' in OFF_BUILD_COMMAND, ""


@check("104. voice mode semantically proves CONFIG_GPTNIX_WATCHER_VOICE=y")
def _c104():
    return bool(re.search(r'(?<!! )grep -qx "CONFIG_GPTNIX_WATCHER_VOICE=y" sdkconfig', VOICE_BUILD_COMMAND)), ""


@check("105. voice mode semantically proves CONFIG_GPTNIX_WATCHER_PROVISION=y is absent")
def _c105():
    return '! grep -qx "CONFIG_GPTNIX_WATCHER_PROVISION=y" sdkconfig' in VOICE_BUILD_COMMAND, ""


@check("106. m3a mode exact three-flag assertion is unchanged by this correction")
def _c106():
    required = [
        'grep -qx "CONFIG_GPTNIX_WATCHER_VOICE=y" sdkconfig',
        'grep -qx "CONFIG_GPTNIX_WATCHER_PROVISION=y" sdkconfig',
        'grep -qx "CONFIG_GPTNIX_WATCHER_SESSION_URL=\\"https://example.invalid/v2/watcher/realtime/session\\"" sdkconfig',
    ]
    missing = [r for r in required if r not in M3A_BUILD_COMMAND]
    return not missing, "missing: %s" % missing


@check("107. no '|| true' weakening in any build-mode assertion command")
def _c107():
    hits = [cmd for cmd in (OFF_BUILD_COMMAND, VOICE_BUILD_COMMAND, M3A_BUILD_COMMAND) if '|| true' in cmd]
    return not hits, "found in %d command(s)" % len(hits)


# ---- Bridge timeout (RC3 fix: bounded backend reads) ----

@check("108. -ProtocolTimeoutSeconds default is 15")
def _c108():
    return "[int]$ProtocolTimeoutSeconds = 15" in BRIDGE_PS1_RAW, ""


@check("109. protocol timeout validation rejects values below 1")
def _c109():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwProtocolTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    return "-ge 1" in body, ""


@check("110. protocol timeout validation rejects values above 15")
def _c110():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwProtocolTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    return "-le 15" in body, ""


@check("111. canonical bounded stream-read helper exists")
def _c111():
    return "function Read-GwStreamExactBounded" in BRIDGE_PS1_RAW, ""


@check("112. monotonic deadline source (Stopwatch) is used, not wall-clock Get-Date, for the bounded read")
def _c112():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Read-GwStreamExactBounded", "function Start-GwBackendProcess")
    return "System.Diagnostics.Stopwatch" in body and "ElapsedMilliseconds" in body, ""


@check("113. live backend TOKEN_FRAME read is wired through the bounded helper")
def _c113():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    idx_bind = live_body.find("$readBackendExact = {")
    idx_forward = live_body.find("Receive-GwTokenFrameAndForward -ReadBytesExact $readBackendExact")
    bound_between = "Read-GwStreamExactBounded" in live_body[idx_bind:idx_forward] if idx_bind != -1 and idx_forward != -1 else False
    return idx_bind != -1 and idx_forward != -1 and bound_between, ""


@check("114. no old naked unbounded backend stream read remains anywhere in the file")
def _c114():
    return "$outStream.Read(" not in BRIDGE_PS1_RAW, ""


@check("115. TOKEN_FRAME header and payload share exactly one deadline (one Stopwatch, created once, before the forwarding call)")
def _c115():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    n_created = len(re.findall(r"\$tokenFrameStopwatch = \[System\.Diagnostics\.Stopwatch\]::StartNew\(\)", live_body))
    idx_created = live_body.find("$tokenFrameStopwatch = [System.Diagnostics.Stopwatch]::StartNew()")
    idx_forward = live_body.find("Receive-GwTokenFrameAndForward -ReadBytesExact $readBackendExact")
    return n_created == 1 and idx_created != -1 and idx_forward != -1 and idx_created < idx_forward, "created=%d" % n_created


@check("116. a failed/timed-out header read cannot reach the serial-write callback (structural: null-check precedes the write)")
def _c116():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    idx_header_check = body.find("if (-not $parsed.Ok")
    idx_write = body.find("& $WriteBytes $frame")
    return idx_header_check != -1 and idx_write != -1 and idx_header_check < idx_write, ""


@check("117. a failed/timed-out (including partial) payload read cannot reach the serial-write callback")
def _c117():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    idx_payload_check = body.find("if ($null -eq $payload)")
    idx_write = body.find("& $WriteBytes $frame")
    return idx_payload_check != -1 and idx_write != -1 and idx_payload_check < idx_write, ""


@check("118. the post-staged backend decision read uses its OWN fresh deadline, separate from the TOKEN_FRAME deadline")
def _c118():
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    has_decision_sw = "$decisionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()" in live_body
    idx_staged_write = live_body.find("$stagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged")
    idx_decision_sw = live_body.find("$decisionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()")
    distinct_from_token_frame_sw = "$decisionStopwatch" != "$tokenFrameStopwatch"
    return (has_decision_sw and idx_staged_write != -1 and idx_decision_sw != -1
        and idx_staged_write < idx_decision_sw and distinct_from_token_frame_sw), ""


# ---- Bridge state (RC2 fix: deterministic SelfTest closure state) ----

@check("119. mutable SelfTest callback indexes use deterministic [pscustomobject] state objects")
def _c119():
    n = len(re.findall(r"\[pscustomobject\]@\{\s*Index\s*=\s*0\s*\}", BRIDGE_PS1_RAW))
    return n >= 4, "found %d" % n


@check("120. the historical bare-scalar closure-mutation pattern is fully absent")
def _c120():
    hits = [s for s in ("$fixtureIndex", "$rxIndex", "$wrongIndex", "$realIndex") if s in BRIDGE_PS1_RAW]
    return not hits, "found: %s" % hits


@check("121. SelfTest's new bounded-read fixtures still open no serial/SSH/network resource")
def _c121():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwSelfTest")
    hits = [s for s in ("SerialPort", "Process]::Start", "Start-GwBackendProcess", "Invoke-WebRequest", "Invoke-RestMethod", "ssh.exe") if s in body]
    return not hits, "found: %s" % hits


# ---- Firmware observability (RC4 fix) ----

@check("122. exactly one active terminal classified log per run")
def _c122():
    n = len(re.findall(r'"\[V2_WATCHER_PROVISION\] terminal: code=%d"', PROVISION_C_CODE))
    return n == 1, "found %d" % n


@check("123. the terminal log lives in the public app_gptnix_watcher_provision_run wrapper")
def _c123():
    body = _extract_c_function(PROVISION_C_CODE, "app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void)\n{", "#else")
    return 'terminal: code=%d' in body, ""


@check("124. s_run_provision_cycle contains zero terminal logs")
def _c124():
    body = _extract_c_function(PROVISION_C_CODE, "static app_gptnix_watcher_provision_result_t s_run_provision_cycle(void)", "app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void)")
    return 'terminal: code=' not in body, ""


@check("125. UART flush occurs after the terminal log and before the return, in the public wrapper")
def _c125():
    body = _extract_c_function(PROVISION_C_CODE, "app_gptnix_watcher_provision_result_t app_gptnix_watcher_provision_run(void)\n{", "#else")
    idx_cycle = body.find("s_run_provision_cycle()")
    idx_log = body.find("terminal: code=%d")
    idx_flush = body.find("uart_flush_input(CONFIG_ESP_CONSOLE_UART_NUM)")
    idx_return = body.find("return result;")
    return (idx_cycle != -1 and idx_log != -1 and idx_flush != -1 and idx_return != -1
        and idx_cycle < idx_log < idx_flush < idx_return), ""


if __name__ == "__main__":
    sys.exit(main())
