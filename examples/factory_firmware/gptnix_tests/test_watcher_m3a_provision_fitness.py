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
        # M3C (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md): the runtime audio bridge milestone this module's own
        # header always said was "a separate, later milestone" -- adds app_gptnix_watcher_voice_send_audio()
        # (mic -> Gemini realtimeInput) and extends WEBSOCKET_EVENT_DATA to also handle READY-state frames
        # (Gemini's spoken response, serverContent.modelTurn.parts[].inlineData -> the audio player, via a
        # synthesized WAV header declaring the fixed 24kHz output rate rather than touching the shared
        # TX/RX I2S/codec clock config). The pre-existing setupComplete/M3A contract is unchanged.
        # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with a long-lived
        # READY session revealed WS control frames (ping/pong/close) were being misclassified as protocol
        # errors, silently breaking every session shortly after reaching READY -- never proven with a
        # long-lived connection before this session. Fixed by skipping control frames entirely.
        # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): RX reassembly buffer + audio chunk
        # bound enlarged 8192->65536 -- a live physical test with real speech showed real Gemini audio
        # response messages (up to 33547 observed bytes) far exceed the original 8192-byte sizing (chosen
        # for the tiny setupComplete message), silently breaking every session on its first real reply.
        # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): a live physical test with real speech
        # proved `data->fin` reflects the WS FRAME's own FIN bit (always 1 for Gemini's non-fragmented
        # frames), not whether esp_websocket_client's internal buffer-chunked delivery has finished --
        # confirmed against the real esp_websocket_client.h source ("payloads exceeding buffer will be
        # posted through multiple events" via payload_offset/payload_len). Every real (large) reply
        # arrived as multiple same-fin=1 chunks; the old check never actually waited. Fixed to compare
        # accumulated bytes against the total payload length instead.
        # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): WS client buffer_size enlarged
        # 4096->32768 -- a live physical test showed the WS text-send call failing for a realistic-size
        # mic audio chunk (~21.4KB once base64-encoded). ESP-IDF's internal auto-fragmentation for
        # oversized sends has known upstream reliability issues; sized generously above the largest
        # realistic outgoing message instead.
        # M3C fix (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): two live multi-turn conversation tests
        # showed the ENTIRE session going silent (not just sends failing -- Gemini's own replies and
        # routine acks stopped too) once the mic-send task fell behind. Tried a dedicated, much shorter
        # GPTNIX_WATCHER_VOICE_AUDIO_SEND_TIMEOUT_MS=300 for the audio-send call site -- a live test then
        # showed a WORSE regression (complete silence, reproduced twice, even before the user spoke):
        # short timeouts made the send task retry in a tight loop, contending for the shared send/receive
        # lock far more often than the original 10s timeout, apparently starving receive processing worse.
        # Reverted GPTNIX_WATCHER_VOICE_AUDIO_SEND_TIMEOUT_MS to 10000 (same value as
        # GPTNIX_WATCHER_VOICE_NETWORK_TIMEOUT_MS, just a separately-named constant) pending a
        # differently-shaped fix.
        # M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): user-reported latency (over a
        # minute) far exceeds what buffer/timeout tuning alone should cause -- added a direct esp_timer_
        # get_time() measurement around the one esp_websocket_client_send_text() call in send_audio() to
        # settle whether the bottleneck is a real achievable-throughput ceiling on this hardware/network
        # path, not app-level tuning. Never logs message content, only elapsed_ms/msg_len/pcm_len.
        # M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): the autonomous synthetic-audio
        # test mode reliably delivers its clip (proven zero-drop across 4 live runs) but the espeak-ng
        # voice hasn't elicited a real Gemini reply -- a synthetic-speech-intelligibility limitation, not
        # a pipeline defect. Added app_gptnix_watcher_voice_send_text_turn(): a `clientContent`/
        # `turnComplete:true` message (per ai.google.dev/api/live) that deterministically triggers a real
        # spoken reply independent of speech recognition -- test/diagnostic use only, never called from
        # the normal microphone-streaming path.
        "5537b104c89180b05d24c1ef10256fe07f9a2dbb",
    "examples/factory_firmware/main/app/app_gptnix_watcher_voice.h":
        # M3C: adds the app_gptnix_watcher_voice_send_audio()/set_audio_callback() declarations (see .c
        # blob comment above) -- this module still never touches the player/recorder APIs itself.
        # M3C diagnostic (plans/M3C_AUDIO_BRIDGE_CHILD_TASK.md follow-up): adds the
        # app_gptnix_watcher_voice_send_text_turn() declaration (see .c blob comment above).
        "38028892fea14ebf6b4b2af1a8520861e131d7c0",
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


def _strip_ps1_comments(text):
    """Single-pass scanner: strips PowerShell # line comments and <# ... #> block comments while correctly
    skipping over '...' / "..." string literals (so a '#' inside a string is never mistaken for a comment
    start) and @'...'@ / @"..."@ here-strings (so the embedded C# Add-Type source block is never partially
    stripped). Needed because this file's own explanatory PROSE comments legitimately name the exact APIs
    (Stream.BeginRead, AsyncWaitHandle, ReadAsync) that "must be absent from real code" checks search for --
    a naive substring search over raw text would false-positive on that documentation."""
    out = []
    i, n = 0, len(text)
    state = None  # None | 'line_comment' | 'block_comment' | 'sq_string' | 'dq_string' | 'here_sq' | 'here_dq'
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
            if c == "#" and c2 == ">":
                state = None
                i += 2
                continue
            i += 1
            continue
        if state == "sq_string":
            out.append(c)
            if c == "'":
                if c2 == "'":
                    out.append(c2)
                    i += 2
                    continue
                state = None
            i += 1
            continue
        if state == "dq_string":
            out.append(c)
            if c == "`" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                state = None
            i += 1
            continue
        if state in ("here_sq", "here_dq"):
            out.append(c)
            if c == "\n":
                closer = "'@" if state == "here_sq" else '"@'
                if text[i + 1:i + 1 + len(closer)] == closer:
                    out.append(closer)
                    i += 1 + len(closer)
                    state = None
                    continue
            i += 1
            continue
        # not inside any special state
        if c == "<" and c2 == "#":
            state = "block_comment"
            i += 2
            continue
        if c == "#":
            state = "line_comment"
            i += 1
            continue
        if c == "'":
            state = "sq_string"
            out.append(c)
            i += 1
            continue
        if c == '"':
            state = "dq_string"
            out.append(c)
            i += 1
            continue
        if c == "@" and c2 == "'":
            state = "here_sq"
            out.append(c)
            out.append(c2)
            i += 2
            continue
        if c == "@" and c2 == '"':
            state = "here_dq"
            out.append(c)
            out.append(c2)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


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
BRIDGE_PS1_CODE = _strip_ps1_comments(BRIDGE_PS1_RAW)
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
    # PR #5 exact-forward correction: the upstream forward is no longer a separate New-GwFrame reconstruction
    # after Confirm-GwDeviceTokenStaged -- $stagedFrame IS the Confirm-GwDeviceTokenStaged return value, so the
    # boundary anchor is the assignment itself, and the write must still come strictly after it.
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    idx_confirm = live_body.find("Confirm-GwDeviceTokenStaged")
    idx_forward = live_body.find("$inStream.Write($stagedFrame")
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
    if idx_bind == -1 or idx_forward == -1:
        return False, ""
    closure_body = live_body[idx_bind:idx_forward]
    direct = "Read-GwStreamExactBounded" in closure_body
    # Bare-name resolution inside .GetNewClosure() throws CommandNotFoundException when the bridge is
    # invoked via `& scriptPath` from an already-running parent script (proven via a live physical
    # failure, not a hypothesis) -- the corrected pattern binds the function reference via
    # ${function:...} before defining the closure, then invokes it through that bound reference.
    ref_match = re.search(r"\$(\w+) = \$\{function:Read-GwStreamExactBounded\}", live_body[:idx_bind])
    via_ref = bool(ref_match) and ("& $%s " % ref_match.group(1)) in closure_body
    return direct or via_ref, "direct=%s via_ref=%s" % (direct, via_ref)


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
    # PR #5 exact-forward correction: boundary anchor moved from the retired New-GwFrame reconstruction to the
    # $stagedFrame assignment (now the Confirm-GwDeviceTokenStaged return value) -- same ordering intent.
    live_body = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
    has_decision_sw = "$decisionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()" in live_body
    idx_staged_write = live_body.find("$stagedFrame = Confirm-GwDeviceTokenStaged")
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


# ===========================================================================
# M3A.3B Correction #2 (Windows PowerShell 5.1 hard-bounded process stdout read) -- 126-160
# ===========================================================================

BOUNDED_READ_TYPE_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "public static class GptnixWatcherBoundedProcessRead", "function New-GwFrame")
READ_HELPER_FN_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "function Read-GwStreamExactBounded", "function Test-GwFrameHeader")
LIVE_BRIDGE_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
SELFTEST_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "function Invoke-GwSelfTest")


@check("126. bridge contains zero .BeginRead( call sites (comment-stripped source)")
def _c126():
    n = len(re.findall(r"\.BeginRead\(", BRIDGE_PS1_CODE))
    return n == 0, "found %d" % n


@check("127. bridge contains zero .EndRead( call sites (comment-stripped source)")
def _c127():
    n = len(re.findall(r"\.EndRead\(", BRIDGE_PS1_CODE))
    return n == 0, "found %d" % n


@check("128. bounded owner does not use AsyncWaitHandle (comment-stripped source)")
def _c128():
    return "AsyncWaitHandle" not in BRIDGE_PS1_CODE, ""


@check("129. bounded owner does not use ReadAsync( as its cancellation mechanism (comment-stripped source)")
def _c129():
    return "ReadAsync(" not in BRIDGE_PS1_CODE, ""


@check("130. exactly one GptnixWatcherBoundedProcessRead type definition")
def _c130():
    n = len(re.findall(r"public static class GptnixWatcherBoundedProcessRead", BRIDGE_PS1_RAW))
    return n == 1, "found %d" % n


@check("131. Add-Type is guarded so the type cannot be defined twice in the same process")
def _c131():
    return "PSTypeName" in BRIDGE_PS1_RAW and "GptnixWatcherBoundedProcessRead" in BRIDGE_PS1_RAW and "Add-Type -TypeDefinition" in BRIDGE_PS1_RAW, ""


@check("132. helper uses a dedicated System.Threading.Thread worker")
def _c132():
    return "new Thread(" in BOUNDED_READ_TYPE_SOURCE, ""


@check("133. helper worker executes a synchronous stream.Read call")
def _c133():
    return "stream.Read(buffer, offset, count)" in BOUNDED_READ_TYPE_SOURCE, ""


@check("134. helper obtains the worker's real Windows thread ID (GetCurrentThreadId)")
def _c134():
    return "GetCurrentThreadId()" in BOUNDED_READ_TYPE_SOURCE, ""


@check("135. helper opens a real worker thread handle (OpenThread) before cancellation")
def _c135():
    return "OpenThread(THREAD_TERMINATE" in BOUNDED_READ_TYPE_SOURCE, ""


@check("136. helper calls CancelSynchronousIo on the real worker thread handle on timeout")
def _c136():
    return "CancelSynchronousIo(threadHandle)" in BOUNDED_READ_TYPE_SOURCE, ""


@check("137. helper closes the real thread handle on every path (CloseHandle in finally)")
def _c137():
    idx_open = BOUNDED_READ_TYPE_SOURCE.find("threadHandle = OpenThread(")
    body_after = BOUNDED_READ_TYPE_SOURCE[idx_open:] if idx_open != -1 else ""
    return idx_open != -1 and "CloseHandle(threadHandle)" in body_after, ""


@check("138. timeout path terminates the backend Process (process.Kill())")
def _c138():
    return "process.Kill();" in BOUNDED_READ_TYPE_SOURCE, ""


@check("139. timeout path closes the backend stdout Stream (stream.Close())")
def _c139():
    return "stream.Close();" in BOUNDED_READ_TYPE_SOURCE, ""


@check("140. explicit GW_READ_CANCEL_GRACE_MS=2000 constant exists and is passed to the helper")
def _c140():
    const_ok = bool(re.search(r"GwReadCancelGraceMs\s*=\s*2000", BRIDGE_PS1_RAW))
    passed_ok = "-BudgetMs $Script:GwReadCancelGraceMs".replace("-BudgetMs ", "") in BRIDGE_PS1_RAW or "$Script:GwReadCancelGraceMs" in READ_HELPER_FN_SOURCE
    return const_ok and passed_ok, "const_ok=%s passed_ok=%s" % (const_ok, passed_ok)


@check("141. the unquiesced-worker path calls exactly one fixed Environment.FailFast")
def _c141():
    n = len(re.findall(r"Environment\.FailFast\(", BOUNDED_READ_TYPE_SOURCE))
    return n == 1, "found %d" % n


@check("142. Environment.FailFast message is a fixed literal with no interpolation/exception object")
def _c142():
    m = re.search(r'Environment\.FailFast\("([^"]*)"\)', BOUNDED_READ_TYPE_SOURCE)
    return bool(m) and "+" not in BOUNDED_READ_TYPE_SOURCE[BOUNDED_READ_TYPE_SOURCE.find("Environment.FailFast") - 40:BOUNDED_READ_TYPE_SOURCE.find("Environment.FailFast")], "match=%s" % bool(m)


@check("143. no buffer clear occurs before the worker-quiescence decision in the timeout branch")
def _c143():
    idx_cancel = BOUNDED_READ_TYPE_SOURCE.find("CancelSynchronousIo(threadHandle)")
    idx_quiesced_decision = BOUNDED_READ_TYPE_SOURCE.find("quiesced = completed;")
    idx_failfast = BOUNDED_READ_TYPE_SOURCE.find("Environment.FailFast(")
    # PowerShell-side Array.Clear on the OWNED buffer must never appear inside the C# type at all -- the C#
    # layer never touches the PowerShell-owned byte[] beyond passing it to stream.Read(); clearing is the
    # PowerShell caller's job, and only after ReadOnceBounded() has already returned (i.e. after quiescence).
    no_clear_in_csharp = "Array.Clear" not in BOUNDED_READ_TYPE_SOURCE
    ordering_ok = idx_cancel != -1 and idx_quiesced_decision != -1 and idx_failfast != -1 and idx_cancel < idx_quiesced_decision < idx_failfast
    return no_clear_in_csharp and ordering_ok, "no_clear_in_csharp=%s ordering_ok=%s" % (no_clear_in_csharp, ordering_ok)


@check("144. Read-GwStreamExactBounded accepts a mandatory Process parameter")
def _c144():
    return bool(re.search(r"\[Parameter\(Mandatory = \$true\)\]\[System\.Diagnostics\.Process\]\$Process", READ_HELPER_FN_SOURCE)), ""


@check("145. live TOKEN_FRAME reads pass the same $proc into the bounded helper")
def _c145():
    direct = len(re.findall(r"Read-GwStreamExactBounded -Stream \$outStream -Process \$proc", LIVE_BRIDGE_SOURCE))
    # Corrected pattern (see check 113): bare-name resolution fails inside .GetNewClosure() when the
    # bridge is invoked via `& scriptPath` from a parent script (proven live) -- each closure instead
    # invokes a pre-bound function reference captured via ${function:Read-GwStreamExactBounded}.
    ref_names = re.findall(r"\$(\w+) = \$\{function:Read-GwStreamExactBounded\}", LIVE_BRIDGE_SOURCE)
    via_ref = 0
    for name in ref_names:
        via_ref += len(re.findall(r"& \$%s -Stream \$outStream -Process \$proc" % re.escape(name), LIVE_BRIDGE_SOURCE))
    n = direct + via_ref
    return n == 2, "found %d (direct=%d via_ref=%d, expect header-read closure + decision-read closure)" % (n, direct, via_ref)


@check("146. TOKEN_FRAME header and payload still share exactly one Stopwatch")
def _c146():
    n = len(re.findall(r"\$tokenFrameStopwatch = \[System\.Diagnostics\.Stopwatch\]::StartNew\(\)", LIVE_BRIDGE_SOURCE))
    return n == 1, "found %d" % n


@check("147. the post-staged decision read still uses its own fresh Stopwatch")
def _c147():
    # PR #5 exact-forward correction: boundary anchor moved from the retired New-GwFrame reconstruction to the
    # $stagedFrame assignment (now the Confirm-GwDeviceTokenStaged return value) -- same ordering intent.
    idx_staged = LIVE_BRIDGE_SOURCE.find("$stagedFrame = Confirm-GwDeviceTokenStaged")
    idx_decision_sw = LIVE_BRIDGE_SOURCE.find("$decisionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()")
    return idx_staged != -1 and idx_decision_sw != -1 and idx_staged < idx_decision_sw, ""


@check("148. no bridge-originated PROVISION_ABORT after TOKEN_STAGED (unaffected by this correction)")
def _c148():
    idx_forward = LIVE_BRIDGE_SOURCE.find("$stagedFrame = New-GwFrame -Type $Script:GwMsgTokenStaged")
    after = LIVE_BRIDGE_SOURCE[idx_forward:] if idx_forward != -1 else LIVE_BRIDGE_SOURCE
    return "New-GwFrame -Type $Script:GwMsgProvisionAbort" not in after, ""


@check("149. serial TOKEN_FRAME write remains reachable only after a complete successful read")
def _c149():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    idx_header_check = body.find("if (-not $parsed.Ok")
    idx_payload_check = body.find("if ($null -eq $payload)")
    idx_write = body.find("& $WriteBytes $frame")
    return (idx_header_check != -1 and idx_payload_check != -1 and idx_write != -1
        and idx_header_check < idx_write and idx_payload_check < idx_write), ""


@check("150. SelfTest includes a real local redirected Process stdout TIMEOUT fixture (J2)")
def _c150():
    return "process_stdout_timeout_not_classified" in SELFTEST_SOURCE and "New-GwSelfTestChildProcess" in SELFTEST_SOURCE, ""


@check("151. SelfTest includes a real local redirected Process stdout PARTIAL fixture (J3)")
def _c151():
    return "process_stdout_partial_not_classified_failure" in SELFTEST_SOURCE, ""


@check("152. SelfTest includes a real local redirected Process stdout SUCCESS fixture (J4)")
def _c152():
    return "process_stdout_success_fixture_failed" in SELFTEST_SOURCE, ""


@check("153. SelfTest includes a real local redirected Process SHARED-DEADLINE fixture (J5)")
def _c153():
    return "process_stdout_shared_deadline_not_classified_failure" in SELFTEST_SOURCE, ""


@check("154. SelfTest's local fixture process is powershell.exe, never the SSH client")
def _c154():
    has_powershell = "FileName = 'powershell.exe'" in _extract_c_function(BRIDGE_PS1_RAW, "function New-GwSelfTestChildProcess")
    hits = [s for s in ("ssh.exe",) if s in SELFTEST_SOURCE]
    return has_powershell and not hits, "has_powershell=%s hits=%s" % (has_powershell, hits)


@check("155. SelfTest still contains no SerialPort.Open path")
def _c155():
    hits = [s for s in ("SerialPort", ".Open()") if s in SELFTEST_SOURCE]
    return not hits, "found: %s" % hits


@check("156. SelfTest still contains no network client/API")
def _c156():
    hits = [s for s in ("Invoke-WebRequest", "Invoke-RestMethod", "System.Net.Sockets", "WebClient", "HttpClient") if s in SELFTEST_SOURCE]
    return not hits, "found: %s" % hits


@check("157. token/string/log secret-hygiene invariants remain (unaffected by this correction)")
def _c157():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
    return "[Array]::Clear($frame" in body and "[Array]::Clear($payload" in body, ""


@check("158. one session HTTP POST / one M2 prepare / one M2 connect call site remain (unaffected, backend/firmware untouched)")
def _c158():
    perform_count = len(re.findall(r"esp_http_client_perform\(", PROVISION_C_CODE))
    prepare_count = len(re.findall(r"app_gptnix_watcher_voice_prepare_session\(", PROVISION_C_CODE))
    connect_count = len(re.findall(r"app_gptnix_watcher_voice_connect\(\)", PROVISION_C_CODE))
    return perform_count == 1 and prepare_count == 1 and connect_count == 1, "perform=%d prepare=%d connect=%d" % (perform_count, prepare_count, connect_count)


@check("159. app_gptnix_watcher_voice.c/.h AND app_wifi.c/.h blob invariants remain untouched")
def _c159():
    paths = [
        "examples/factory_firmware/main/app/app_gptnix_watcher_voice.c",
        "examples/factory_firmware/main/app/app_gptnix_watcher_voice.h",
        "examples/factory_firmware/main/app/app_wifi.c",
        "examples/factory_firmware/main/app/app_wifi.h",
    ]
    bad = [p for p in paths if not _protected_matches(p)]
    return not bad, "mismatched: %s" % bad


@check("160. workflow remains pinned to IDF 5.2.1 / esp32s3 / Windows selftest (READ ONLY in this correction)")
def _c160():
    idf_ok = len(re.findall(r"esp_idf_version:\s*v5\.2\.1", WORKFLOW_RAW)) >= 3
    target_ok = len(re.findall(r"target:\s*esp32s3", WORKFLOW_RAW)) >= 3
    windows_ok = "m3a-bridge-selftest" in WORKFLOW_RAW and "windows-2022" in WORKFLOW_RAW
    return idf_ok and target_ok and windows_ok, "idf_ok=%s target_ok=%s windows_ok=%s" % (idf_ok, target_ok, windows_ok)


# --- Correction #3: retire the obsolete null-Process SelfTest fixtures ------------------------------------

@check("161. zero executable -Process $null call sites anywhere in the bridge (comment-stripped source)")
def _c161():
    n = len(re.findall(r"-Process \$null\b", BRIDGE_PS1_CODE))
    return n == 0, "found %d" % n


@check("162. Read-GwStreamExactBounded still declares a mandatory, typed, non-null Process parameter")
def _c162():
    ok = bool(re.search(r"\[Parameter\(Mandatory = \$true\)\]\[System\.Diagnostics\.Process\]\$Process", READ_HELPER_FN_SOURCE))
    return ok, ""


@check("163. no [AllowNull()] is attached to the Process parameter (or anywhere in the bridge)")
def _c163():
    n = len(re.findall(r"AllowNull", BRIDGE_PS1_CODE))
    return n == 0, "found %d" % n


@check("164. live TOKEN_FRAME bounded read still passes -Process $proc on the shared TOKEN_FRAME Stopwatch")
def _c164():
    ok = bool(re.search(r"-Process \$proc -Count \$count -Stopwatch \$tokenFrameStopwatch", LIVE_BRIDGE_SOURCE))
    return ok, ""


@check("165. live post-staged decision bounded read still passes -Process $proc on the fresh decision Stopwatch")
def _c165():
    ok = bool(re.search(r"-Process \$proc -Count \$count -Stopwatch \$decisionStopwatch", LIVE_BRIDGE_SOURCE))
    return ok, ""


@check("166. real redirected-Process J2 hard-timeout fixture still exists against a real child Process")
def _c166():
    ok = ("process_stdout_timeout_not_classified" in SELFTEST_SOURCE
          and "childJ2.StandardOutput.BaseStream" in SELFTEST_SOURCE
          and "-Process $childJ2" in SELFTEST_SOURCE)
    return ok, ""


@check("167. real redirected-Process J3 partial-timeout fixture still exists against a real child Process")
def _c167():
    ok = ("process_stdout_partial_not_classified_failure" in SELFTEST_SOURCE
          and "childJ3.StandardOutput.BaseStream" in SELFTEST_SOURCE
          and "-Process $childJ3" in SELFTEST_SOURCE)
    return ok, ""


@check("168. J2 and J3 both read from the actual .StandardOutput.BaseStream transport primitive")
def _c168():
    ok = "childJ2.StandardOutput.BaseStream" in SELFTEST_SOURCE and "childJ3.StandardOutput.BaseStream" in SELFTEST_SOURCE
    return ok, ""


@check("169. J2 and J3 both pass a real, non-null child Process object into -Process (never $null)")
def _c169():
    ok = "-Process $childJ2" in SELFTEST_SOURCE and "-Process $childJ3" in SELFTEST_SOURCE
    no_null = "-Process $null" not in SELFTEST_SOURCE
    return ok and no_null, "ok=%s no_null=%s" % (ok, no_null)


@check("170. obsolete AnonymousPipe null-Process timeout/partial fixture symbols are fully absent")
def _c170():
    retired_symbols = (
        "pipeServerA", "pipeClientA", "resultA",
        "pipeServerB", "pipeClientB", "partialHeader", "readPartialExact",
        "GwSelfTestPartialWriteInvoked", "captureWritePartial",
        "bounded_read_timeout_not_classified", "bounded_read_timeout_wrong_reason",
        "partial_frame_timeout_not_classified_failure", "timeout_read_invoked_serial_write",
    )
    present = [s for s in retired_symbols if s in BRIDGE_PS1_RAW]
    return not present, "still present: %s" % present


@check("171. J4 successful real-Process fixture remains")
def _c171():
    return "process_stdout_success_fixture_failed" in SELFTEST_SOURCE and "-Process $childJ4" in SELFTEST_SOURCE, ""


@check("172. J5 shared-TOKEN_FRAME-deadline real-Process fixture remains")
def _c172():
    return "process_stdout_shared_deadline_not_classified_failure" in SELFTEST_SOURCE and "-Process $childJ5" in SELFTEST_SOURCE, ""


@check("173. J6 post-staged-decision real-Process fixture remains")
def _c173():
    return "process_stdout_decision_timeout_not_classified" in SELFTEST_SOURCE and "-Process $childJ6" in SELFTEST_SOURCE, ""


@check("174. Correction #2 bounded-read protections are unweakened by this correction")
def _c174():
    beginread_ok = len(re.findall(r"\.BeginRead\(", BRIDGE_PS1_CODE)) == 0
    endread_ok = len(re.findall(r"\.EndRead\(", BRIDGE_PS1_CODE)) == 0
    asyncwait_ok = "AsyncWaitHandle" not in BRIDGE_PS1_CODE
    worker_ok = "new Thread(" in BOUNDED_READ_TYPE_SOURCE
    cancel_ok = "CancelSynchronousIo(threadHandle)" in BOUNDED_READ_TYPE_SOURCE
    failfast_ok = len(re.findall(r"Environment\.FailFast\(", BOUNDED_READ_TYPE_SOURCE)) == 1
    shared_deadline_ok = bool(re.search(r"-Process \$proc -Count \$count -Stopwatch \$tokenFrameStopwatch", LIVE_BRIDGE_SOURCE))
    fresh_decision_ok = bool(re.search(r"-Process \$proc -Count \$count -Stopwatch \$decisionStopwatch", LIVE_BRIDGE_SOURCE))
    all_ok = beginread_ok and endread_ok and asyncwait_ok and worker_ok and cancel_ok and failfast_ok and shared_deadline_ok and fresh_decision_ok
    return all_ok, ("beginread_ok=%s endread_ok=%s asyncwait_ok=%s worker_ok=%s cancel_ok=%s failfast_ok=%s "
                     "shared_deadline_ok=%s fresh_decision_ok=%s") % (
        beginread_ok, endread_ok, asyncwait_ok, worker_ok, cancel_ok, failfast_ok, shared_deadline_ok, fresh_decision_ok)


# ===========================================================================
# M3A TOKEN_STAGED serial resynchronization fix (175-182)
# ===========================================================================

RESYNC_FN_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "function Read-GwFrameHeaderResynchronized", "function Receive-GwTokenFrameAndForward")
CONFIRM_STAGED_SOURCE = _extract_c_function(BRIDGE_PS1_RAW, "function Confirm-GwDeviceTokenStaged", "function Read-GwStreamExactBounded")


@check("175. resync scanner never fabricates a success -- Ok is only ever assigned from Test-GwFrameHeader's own result")
def _c175():
    hardcoded_true = len(re.findall(r"Ok\s*=\s*\$true", RESYNC_FN_SOURCE)) > 0
    from_parsed = "Ok = $parsed.Ok" in RESYNC_FN_SOURCE
    return (not hardcoded_true) and from_parsed, "hardcoded_true=%s from_parsed=%s" % (hardcoded_true, from_parsed)


@check("176. resync scanner never stringifies or prints scanned noise/header bytes")
def _c176():
    string_hits = [s for s in ("[string]$b", "[string]$window", "[string]$rest", "[string]$header", "GetString(") if s in RESYNC_FN_SOURCE]
    print_hits = [s for s in re.findall(r"Write-(?:Host|Output)\s+\$\w+", RESYNC_FN_SOURCE)]
    return not string_hits and not print_hits, "string_hits=%s print_hits=%s" % (string_hits, print_hits)


@check("177. resync scanner is bounded -- only one while-loop condition tests the caller-owned deadline, plus one fixed noise-count bound")
def _c177():
    deadline_loops = len(re.findall(r"while\s*\(\(Get-Date\)\s*-lt\s*\$Deadline\)|while\s*\(\(Get-Date\)\s*-ge\s*\$Deadline\)", RESYNC_FN_SOURCE))
    has_scan_limit = "scanned -gt $MaxNoiseBytes" in RESYNC_FN_SOURCE
    return deadline_loops >= 1 and has_scan_limit, "deadline_loops=%d has_scan_limit=%s" % (deadline_loops, has_scan_limit)


@check("178. Confirm-GwDeviceTokenStaged uses the resync-based -ReadByte/-Deadline signature, not the retired -ReadBytesExact positional reader")
def _c178():
    sig_ok = "[scriptblock]$ReadByte" in CONFIRM_STAGED_SOURCE and "[datetime]$Deadline" in CONFIRM_STAGED_SOURCE
    old_gone = "ReadBytesExact" not in CONFIRM_STAGED_SOURCE
    calls_resync = "Read-GwFrameHeaderResynchronized -ReadByte $ReadByte -Deadline $Deadline" in CONFIRM_STAGED_SOURCE
    return sig_ok and old_gone and calls_resync, "sig_ok=%s old_gone=%s calls_resync=%s" % (sig_ok, old_gone, calls_resync)


@check("179. Confirm-GwDeviceTokenStaged still throws (never returns falsy) on any non-OK/wrong-type/nonzero-payload result")
def _c179():
    return bool(re.search(r'if\s*\(-not \$parsed\.Ok -or \$parsed\.Type -ne \$Script:GwMsgTokenStaged -or \$parsed\.Length -ne 0\)\s*\{\s*throw', CONFIRM_STAGED_SOURCE)), ""


@check("180. Invoke-GwLiveBridge's TOKEN_STAGED call site reuses the single existing device-byte reader -- no second reader/owner introduced")
def _c180():
    reader_uses = len(re.findall(r"\$readDeviceByte\b", LIVE_BRIDGE_SOURCE))
    confirm_call = "Confirm-GwDeviceTokenStaged -ReadByte $readDeviceByte -Deadline $tokenStagedDeadline" in LIVE_BRIDGE_SOURCE
    no_old_exact_reader = "$readSerialExact" not in LIVE_BRIDGE_SOURCE
    return reader_uses >= 2 and confirm_call and no_old_exact_reader, "reader_uses=%d confirm_call=%s no_old_exact_reader=%s" % (reader_uses, confirm_call, no_old_exact_reader)


@check("181. TOKEN_STAGED deadline is a single fresh budget derived from -ProtocolTimeoutSeconds, matching the retired reader's own budget concept")
def _c181():
    return "$tokenStagedDeadline = (Get-Date).AddSeconds($ProtocolTimeoutSeconds)" in LIVE_BRIDGE_SOURCE, ""


@check("182. GwMaxResyncNoiseBytes is a fixed, bounded, positive constant")
def _c182():
    # Upper bound widened from the original 65536 to 250000 by the M3A TOKEN_STAGED RX-backlog fix: the
    # canonical constant itself became the physically-derived 172800 (115200 baud / 10 line-bits * 15s, see
    # check 189), which exceeds the old arbitrary guess. The invariant this check actually protects -- fixed,
    # bounded, positive, nowhere near an unbounded/Int32.MaxValue-style value -- is unchanged and still enforced;
    # only the specific historical magic number has been corrected to match the now-canonical value.
    m = re.search(r"\$Script:GwMaxResyncNoiseBytes\s*=\s*(\d+)", BRIDGE_PS1_RAW)
    if not m:
        return False, "constant not found"
    value = int(m.group(1))
    return 0 < value <= 250000, "value=%d" % value


# ===========================================================================
# PR #5 architect-review correction: exact device TOKEN_STAGED forwarding
# ownership (183-188). A green test on Read-GwFrameHeaderResynchronized's own
# Header field (checks 175-182) does NOT prove Confirm-GwDeviceTokenStaged
# hands that value to its caller, nor that Invoke-GwLiveBridge forwards it
# upstream instead of fabricating a fresh frame -- that exact gap is what let
# a reconstructed-frame implementation pass the prior green CI run. These
# checks specifically test the ownership/forwarding chain, not the scanner.
# ===========================================================================

@check("183. Confirm-GwDeviceTokenStaged returns the validated device header bytes on success, never a bare boolean")
def _c183():
    returns_header = "return [byte[]]$parsed.Header" in CONFIRM_STAGED_SOURCE
    no_bare_true_return = not re.search(r"return\s+\$true\b", CONFIRM_STAGED_SOURCE)
    return returns_header and no_bare_true_return, "returns_header=%s no_bare_true_return=%s" % (returns_header, no_bare_true_return)


@check("184. Invoke-GwLiveBridge's TOKEN_STAGED call site assigns the Confirm-GwDeviceTokenStaged return value -- never discards it")
def _c184():
    assigns = "$stagedFrame = Confirm-GwDeviceTokenStaged -ReadByte $readDeviceByte -Deadline $tokenStagedDeadline" in LIVE_BRIDGE_SOURCE
    discards = "Confirm-GwDeviceTokenStaged -ReadByte $readDeviceByte -Deadline $tokenStagedDeadline | Out-Null" in LIVE_BRIDGE_SOURCE
    return assigns and not discards, "assigns=%s discards=%s" % (assigns, discards)


@check("185. the exact assigned $stagedFrame reaches the live upstream write with no reconstruction in between")
def _c185():
    assign_idx = LIVE_BRIDGE_SOURCE.find("$stagedFrame = Confirm-GwDeviceTokenStaged")
    write_idx = LIVE_BRIDGE_SOURCE.find("$inStream.Write($stagedFrame")
    if assign_idx == -1 or write_idx == -1 or assign_idx >= write_idx:
        return False, "assign_idx=%d write_idx=%d" % (assign_idx, write_idx)
    between = LIVE_BRIDGE_SOURCE[assign_idx:write_idx]
    no_reconstruction = "New-GwFrame" not in between
    return no_reconstruction, "between=%r" % between


@check("186. Invoke-GwLiveBridge's live path contains zero New-GwFrame(TOKEN_STAGED) reconstruction calls")
def _c186():
    hits = LIVE_BRIDGE_SOURCE.count("New-GwFrame -Type $Script:GwMsgTokenStaged")
    return hits == 0, "hits=%d" % hits


@check("187. any New-GwFrame(TOKEN_STAGED) construction file-wide is confined to Invoke-GwSelfTest fixture setup only")
def _c187():
    total = BRIDGE_PS1_RAW.count("New-GwFrame -Type $Script:GwMsgTokenStaged")
    in_selftest = SELFTEST_SOURCE.count("New-GwFrame -Type $Script:GwMsgTokenStaged")
    return total > 0 and total - in_selftest == 0, "total=%d in_selftest=%d" % (total, in_selftest)


@check("188. the corrected $stagedFrame device bytes are never stringified, logged, or printed")
def _c188():
    string_hits = [s for s in ("[string]$stagedFrame", "GetString($stagedFrame") if s in LIVE_BRIDGE_SOURCE]
    print_hits = re.findall(r"Write-(?:Host|Output)\s+\$stagedFrame\b", LIVE_BRIDGE_SOURCE)
    return not string_hits and not print_hits, "string_hits=%s print_hits=%s" % (string_hits, print_hits)


# ===========================================================================
# M3A TOKEN_STAGED RX-backlog fix (189-208): the -BeforeWrite RX barrier hook on
# Receive-GwTokenFrameAndForward, and the physically-derived 172800-byte resync ceiling.
# ===========================================================================

RECEIVE_TOKEN_FRAME_SOURCE = _extract_c_function(
    BRIDGE_PS1_RAW, "function Receive-GwTokenFrameAndForward", "function Confirm-GwDeviceTokenStaged")
CONFIRM_TOKEN_STAGED_SOURCE = _extract_c_function(
    BRIDGE_PS1_RAW, "function Confirm-GwDeviceTokenStaged", "function Read-GwStreamExactBounded")


@check("189. GwMaxResyncNoiseBytes is the physically-derived 172800-byte ceiling (115200 baud / 10 line-bits * 15s), not an arbitrary retry budget")
def _c189():
    m = re.search(r"\$Script:GwMaxResyncNoiseBytes\s*=\s*(\d+)", BRIDGE_PS1_RAW)
    ok = bool(m) and m.group(1) == "172800" and 115200 // 10 * 15 == 172800
    return ok, "value=%s" % (m.group(1) if m else None)


@check("190. the retired 512-byte resync ceiling is no longer assigned to GwMaxResyncNoiseBytes")
def _c190():
    hits = re.findall(r"\$Script:GwMaxResyncNoiseBytes\s*=\s*512\b", BRIDGE_PS1_RAW)
    return len(hits) == 0, "hits=%d" % len(hits)


@check("191. ProtocolTimeoutSeconds max remains 15 -- unchanged by this correction")
def _c191():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwProtocolTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    ok = "-le 15" in body and "-le 16" not in body and "-le 20" not in body
    return ok, "body_has_le_15=%s" % ("-le 15" in body)


@check("192. default BaudRate remains 115200 -- unchanged by this correction")
def _c192():
    return "[int]$BaudRate = 115200" in BRIDGE_PS1_RAW, ""


@check("193. Receive-GwTokenFrameAndForward owns the pre-write RX-barrier hook (-BeforeWrite, optional scriptblock)")
def _c193():
    return "[scriptblock]$BeforeWrite" in RECEIVE_TOKEN_FRAME_SOURCE, ""


@check("194. the live RX barrier is implemented via $port.DiscardInBuffer()")
def _c194():
    return "$port.DiscardInBuffer()" in LIVE_BRIDGE_SOURCE, ""


@check("195. the live path has exactly one DiscardInBuffer call site file-wide")
def _c195():
    hits = BRIDGE_PS1_RAW.count("$port.DiscardInBuffer()")
    return hits == 1, "hits=%d" % hits


@check("196. no DiscardOutBuffer call exists anywhere -- the barrier only ever discards stale RX, never TX")
def _c196():
    return "DiscardOutBuffer(" not in BRIDGE_PS1_RAW, ""


@check("197. inside Receive-GwTokenFrameAndForward, the -BeforeWrite invocation is structurally before the WriteBytes invocation")
def _c197():
    before_idx = RECEIVE_TOKEN_FRAME_SOURCE.find("& $BeforeWrite")
    write_idx = RECEIVE_TOKEN_FRAME_SOURCE.find("& $WriteBytes $frame")
    ok = before_idx != -1 and write_idx != -1 and before_idx < write_idx
    return ok, "before_idx=%d write_idx=%d" % (before_idx, write_idx)


@check("198. the -BeforeWrite hook is invoked with zero arguments -- it never receives token/frame bytes")
def _c198():
    m = re.search(r"&\s+\$BeforeWrite([^\r\n]*)", RECEIVE_TOKEN_FRAME_SOURCE)
    trailing = m.group(1).strip() if m else None
    return bool(m) and trailing == "", "trailing=%r" % trailing


@check("199. a malformed/incomplete backend TOKEN_FRAME cannot reach WriteBytes -- both validation throws precede the barrier/write try block")
def _c199():
    idx_header_throw = RECEIVE_TOKEN_FRAME_SOURCE.find('throw "gw_token_frame_invalid:')
    idx_payload_throw = RECEIVE_TOKEN_FRAME_SOURCE.find("throw 'gw_token_frame_payload_read_failed'")
    idx_try = RECEIVE_TOKEN_FRAME_SOURCE.find("try {")
    ok = -1 not in (idx_header_throw, idx_payload_throw, idx_try) and idx_header_throw < idx_try and idx_payload_throw < idx_try
    return ok, "header=%d payload=%d try=%d" % (idx_header_throw, idx_payload_throw, idx_try)


@check("200. Confirm-GwDeviceTokenStaged's TOKEN_STAGED scanner remains deadline-owned (mandatory -Deadline), unchanged by this correction")
def _c200():
    ok = "[Parameter(Mandatory = $true)][datetime]$Deadline" in CONFIRM_TOKEN_STAGED_SOURCE
    return ok, ""


@check("201. Confirm-GwDeviceTokenStaged still returns the exact validated device header bytes -- the PR #5 exact-forwarding invariant is unaffected by this correction")
def _c201():
    return "return [byte[]]$parsed.Header" in CONFIRM_TOKEN_STAGED_SOURCE, ""


@check("202. Invoke-GwLiveBridge's live path still contains zero New-GwFrame(TOKEN_STAGED) reconstruction calls -- regression of the PR #5 fix")
def _c202():
    hits = LIVE_BRIDGE_SOURCE.count("New-GwFrame -Type $Script:GwMsgTokenStaged")
    return hits == 0, "hits=%d" % hits


@check("203. DtrEnable remains false -- unchanged by this correction")
def _c203():
    return "$port.DtrEnable = $false" in LIVE_BRIDGE_SOURCE, ""


@check("204. RtsEnable remains false -- unchanged by this correction")
def _c204():
    return "$port.RtsEnable = $false" in LIVE_BRIDGE_SOURCE, ""


@check("205. the bridge still starts the backend SSH process only after a real device BRIDGE_READY -- Wait-GwBridgeReady precedes Start-GwBackendProcess")
def _c205():
    idx_ready = LIVE_BRIDGE_SOURCE.find("Wait-GwBridgeReady -ReadByte $readDeviceByte")
    idx_ssh = LIVE_BRIDGE_SOURCE.find("Start-GwBackendProcess -SshTarget")
    ok = idx_ready != -1 and idx_ssh != -1 and idx_ready < idx_ssh
    return ok, "ready_idx=%d ssh_idx=%d" % (idx_ready, idx_ssh)


@check("206. the RX barrier closure and hook never stringify/convert the token/frame material they run alongside")
def _c206():
    hits = [s for s in ("[string]$discardDeviceInput", "GetString($discardDeviceInput", "$discardDeviceInput.ToString(") if s in BRIDGE_PS1_RAW]
    return not hits, "hits=%s" % hits


@check("207. the device_rx_barrier failure label is a fixed non-interpolated string literal -- never echoes the caller's raw exception or transport internals")
def _c207():
    m = re.search(r"Write-GwClassifiedError\s+-Message\s+('[^'\n]*device_rx_barrier[^'\n]*')", LIVE_BRIDGE_SOURCE)
    literal = m.group(1) if m else None
    ok = bool(m) and "$" not in literal
    return ok, "literal=%r" % literal


@check("208. the RX barrier path never writes a temp file, sets an environment variable, or otherwise persists token/frame material")
def _c208():
    hits = [s for s in ("Out-File", "Set-Content", "[System.IO.File]::Write", "$env:") if s in RECEIVE_TOKEN_FRAME_SOURCE]
    return not hits, "hits=%s" % hits


# ===========================================================================
# Live-output / exit-status fix (209-220): the top-level launcher no longer captures
# Invoke-GwLiveBridge's ENTIRE success/pipeline stream via `exit (Invoke-GwLiveBridge ...)`
# -- a construction that swallowed every live [M3A_BRIDGE] diagnostic and was physically
# reproduced to do so. Diagnostics inside Invoke-GwLiveBridge now use Write-Host (a
# separate, uncapturable stream); the launcher captures only the function's real `return`
# value and validates it against the function's actual exit contract before `exit`.
# Checks below use the comment-stripped BRIDGE_PS1_CODE (not the raw/commented source) so
# that this fix's own explanatory comments -- which necessarily quote the old buggy
# `exit (Invoke-GwLiveBridge ...)` construction as prose -- can never be mistaken for a
# structural match, matching the existing BRIDGE_PS1_CODE convention already used by
# checks in the 140s/1370s range above.
# ===========================================================================

LIVE_BRIDGE_CODE = _extract_c_function(BRIDGE_PS1_CODE, "function Invoke-GwLiveBridge", "function Invoke-GwSelfTest")
LAUNCHER_CODE = _extract_c_function(BRIDGE_PS1_CODE, "if ($SelfTest)")
RESOLVE_EXIT_HELPER_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Resolve-GwLiveBridgeExitCode", "function Invoke-GwLiveBridge")
SELFTEST_BODY_CODE = _extract_c_function(BRIDGE_PS1_CODE, "function Invoke-GwSelfTest", "if ($SelfTest)")


@check("209. the top-level live invocation no longer captures Invoke-GwLiveBridge's output stream inside exit(...)")
def _c209():
    return "exit (Invoke-GwLiveBridge" not in LAUNCHER_CODE, ""


@check("210. Invoke-GwLiveBridge's diagnostic stream is Write-Host only -- zero Write-Output calls remain in its body")
def _c210():
    n_output = LIVE_BRIDGE_CODE.count("Write-Output")
    n_host = LIVE_BRIDGE_CODE.count("Write-Host")
    return n_output == 0 and n_host >= 6, "write_output=%d write_host=%d" % (n_output, n_host)


@check("211. the COMMIT diagnostic remains observable")
def _c211():
    return "Write-Host '[M3A_BRIDGE] decision: commit'" in LIVE_BRIDGE_CODE, ""


@check("212. the ABORT diagnostic remains observable")
def _c212():
    return "Write-Host '[M3A_BRIDGE] decision: abort'" in LIVE_BRIDGE_CODE, ""


@check("213. the device READY observation diagnostics (true and timeout) remain observable")
def _c213():
    n_true = LIVE_BRIDGE_CODE.count("Write-Host '[M3A_BRIDGE] device_ready: true'")
    has_timeout = "Write-Host '[M3A_BRIDGE] device_ready: timeout'" in LIVE_BRIDGE_CODE
    # Two true occurrences: the BRIDGE_READY wait, and the later diagnostics-only READY window.
    return n_true >= 2 and has_timeout, "true_count=%d has_timeout=%s" % (n_true, has_timeout)


@check("214. a malformed/non-integer/out-of-contract live result fails closed to a non-zero exit, never a silent exit 0")
def _c214():
    has_type_check = "-isnot [int]" in RESOLVE_EXIT_HELPER_CODE
    has_set_check = "-notcontains $result" in RESOLVE_EXIT_HELPER_CODE
    idx_check = RESOLVE_EXIT_HELPER_CODE.find("-notcontains $result")
    idx_return2 = RESOLVE_EXIT_HELPER_CODE.find("return 2", idx_check) if idx_check != -1 else -1
    fails_closed = idx_check != -1 and idx_return2 != -1 and idx_check < idx_return2
    ok = has_type_check and has_set_check and fails_closed
    return ok, "type_check=%s set_check=%s fails_closed=%s idx_check=%d idx_return2=%d" % (
        has_type_check, has_set_check, fails_closed, idx_check, idx_return2)


@check("215. the validated live exit-code contract is exactly {0, 2} -- the function's own real return values, never invented, and defined exactly once file-wide")
def _c215():
    n = BRIDGE_PS1_CODE.count("$Script:GwLiveBridgeExitCodes = @(0, 2)")
    return n == 1, "count=%d" % n


@check("215b. the production top-level launcher calls Resolve-GwLiveBridgeExitCode -- not an inline re-implementation of the validation logic")
def _c215b():
    calls_helper = "Resolve-GwLiveBridgeExitCode -Invoke" in LAUNCHER_CODE
    no_inline_type_check = "-isnot [int]" not in LAUNCHER_CODE
    return calls_helper and no_inline_type_check, "calls_helper=%s no_inline_type_check=%s" % (calls_helper, no_inline_type_check)


@check("215c. the -SelfTest dynamic regression cases call the SAME Resolve-GwLiveBridgeExitCode owner the production launcher calls -- not a copy or parallel validator")
def _c215c():
    n = SELFTEST_BODY_CODE.count("Resolve-GwLiveBridgeExitCode -Invoke")
    return n >= 7, "count=%d" % n


@check("215d. no second/duplicate live-result validation logic exists outside Resolve-GwLiveBridgeExitCode")
def _c215d():
    # The compound malformed-result predicate (type check AND allowed-set check together) is the actual
    # validation logic being guarded against duplication -- not the bare `-isnot [int]` operator, which L1/L2
    # legitimately reuse for unrelated SelfTest stream-observation filtering (separating a merged 6>&1
    # int-plus-diagnostic collection), not live-result validation.
    n_compound = BRIDGE_PS1_CODE.count("-isnot [int] -or ($Script:GwLiveBridgeExitCodes -notcontains")
    return n_compound == 1, "count=%d" % n_compound


@check("216. -SelfTest's own output/exit semantics are untouched by this fix -- still Write-Output, still plain exit 0/1 statements")
def _c216():
    has_pass = "Write-Output '[M3A_BRIDGE] selftest: PASS'" in BRIDGE_PS1_CODE
    has_fail = "[M3A_BRIDGE] selftest: FAIL" in BRIDGE_PS1_CODE
    return has_pass and has_fail, "has_pass=%s has_fail=%s" % (has_pass, has_fail)


@check("217. Invoke-GwLiveBridge's diagnostic success stream is fully eliminated -- redundant confirmation alongside 210")
def _c217():
    return LIVE_BRIDGE_CODE.count("Write-Output") == 0, ""


@check("218. exact-device TOKEN_STAGED forwarding (PR #5) is unaffected -- still assigned from Confirm-GwDeviceTokenStaged, never a fabricated New-GwFrame in the live path")
def _c218():
    assigns = "$stagedFrame = Confirm-GwDeviceTokenStaged" in LIVE_BRIDGE_CODE
    no_fabricate = "New-GwFrame -Type $Script:GwMsgTokenStaged" not in LIVE_BRIDGE_CODE
    return assigns and no_fabricate, "assigns=%s no_fabricate=%s" % (assigns, no_fabricate)


@check("219. the RX backlog barrier (PR #6) remains the ONE live DiscardInBuffer call site file-wide -- unaffected by this fix")
def _c219():
    n = BRIDGE_PS1_CODE.count("$port.DiscardInBuffer()")
    return n == 1, "count=%d" % n


@check("220. the live success/abort/failure exit-status contract is unchanged: exactly 3 failure `return 2` sites and 2 success/abort `return 0` sites")
def _c220():
    n2 = len(re.findall(r"\breturn 2\b", LIVE_BRIDGE_CODE))
    n0 = len(re.findall(r"\breturn 0\b", LIVE_BRIDGE_CODE))
    return n2 == 3 and n0 == 2, "return_2=%d return_0=%d" % (n2, n0)


# ===========================================================================
# Classified failure exit semantics fix (221-236): $ErrorActionPreference = 'Stop' is set at
# top scope, so an unqualified Write-Error anywhere in this file is promoted to a terminating
# error and aborts the current scope before the immediately-following `return 2` / `exit 2`
# ever executes. Write-GwClassifiedError is now the sole owner of every classified bridge
# error emission (error stream only, -ErrorAction Continue pinned once), used by both the
# live-mode failure paths inside Invoke-GwLiveBridge/Resolve-GwLiveBridgeExitCode and the
# top-level entrypoint argument-validation gate -- and by the new dynamic L8/L9 -SelfTest
# cases below, which hermetically re-prove on real Windows PowerShell that the classified-
# error-then-return-2/exit-2 path is actually reachable, not merely structurally present.
# ===========================================================================

CLASSIFIED_ERROR_HELPER_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Write-GwClassifiedError", "function Resolve-GwLiveBridgeExitCode")
CHILD_SCRIPT_HELPER_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Invoke-GwChildProcessForSelfTest", "function Write-GwClassifiedError")


@check("221. Write-GwClassifiedError is defined exactly once file-wide -- the sole owner of every classified bridge error emission")
def _c221():
    n = BRIDGE_PS1_CODE.count("function Write-GwClassifiedError")
    return n == 1, "count=%d" % n


@check("222. Write-GwClassifiedError contains exactly one executable Write-Error, with explicit -ErrorAction Continue -- so it can never itself become a terminating error under the file's own $ErrorActionPreference = 'Stop'")
def _c222():
    body = CLASSIFIED_ERROR_HELPER_CODE
    n_write_error = body.count("Write-Error")
    has_continue = "Write-Error -Message $Message -ErrorAction Continue" in body
    return n_write_error == 1 and has_continue, "write_error_count=%d has_continue=%s" % (n_write_error, has_continue)


@check("223. the global $ErrorActionPreference = 'Stop' default is unchanged by this correction -- still set exactly once, at top scope")
def _c223():
    # Comment-stripped BRIDGE_PS1_CODE, not BRIDGE_PS1_RAW: this fix's own explanatory comments necessarily
    # quote the literal `$ErrorActionPreference = 'Stop'` as prose (explaining WHY the helper exists), which
    # must never be mistaken for a second real assignment.
    n = BRIDGE_PS1_CODE.count("$ErrorActionPreference = 'Stop'")
    return n == 1, "count=%d" % n


@check("224. no raw, unqualified Write-Error escapes Write-GwClassifiedError anywhere in the file -- every classified/entrypoint emission goes through the single owner")
def _c224():
    n = BRIDGE_PS1_CODE.count("Write-Error")
    return n == 1, "count=%d (expected exactly 1, inside Write-GwClassifiedError's own body)" % n


@check("225. Write-GwClassifiedError is invoked from exactly 13 call sites file-wide -- the 12 real production classified-failure paths (11 pre-existing plus the new -VoiceReadyTimeoutSeconds entrypoint validation) plus the L8 SelfTest synthetic invoker")
def _c225():
    n = BRIDGE_PS1_CODE.count("Write-GwClassifiedError -Message")
    n_production = LIVE_BRIDGE_CODE.count("Write-GwClassifiedError -Message") + LAUNCHER_CODE.count(
        "Write-GwClassifiedError -Message") + RESOLVE_EXIT_HELPER_CODE.count("Write-GwClassifiedError -Message")
    return n == 13 and n_production == 12, "count=%d n_production=%d" % (n, n_production)


@check("226. the device_ready timeout classified failure uses Write-GwClassifiedError")
def _c226():
    return "Write-GwClassifiedError -Message '[M3A_BRIDGE] device_ready: timeout" in LIVE_BRIDGE_CODE, ""


@check("227. both the RX-barrier and backend TOKEN_FRAME classified failure branches use Write-GwClassifiedError")
def _c227():
    has_barrier = "Write-GwClassifiedError -Message '[M3A_BRIDGE] device_rx_barrier: failed'" in LIVE_BRIDGE_CODE
    has_frame = "Write-GwClassifiedError -Message '[M3A_BRIDGE] backend_token_frame: bounded read failed or frame invalid'" in LIVE_BRIDGE_CODE
    return has_barrier and has_frame, "has_barrier=%s has_frame=%s" % (has_barrier, has_frame)


@check("228. the backend_decision malformed classified failure uses Write-GwClassifiedError")
def _c228():
    return "Write-GwClassifiedError -Message '[M3A_BRIDGE] backend_decision: malformed'" in LIVE_BRIDGE_CODE, ""


@check("229. all seven top-level entrypoint argument-validation classified failures (the six pre-existing plus the new -VoiceReadyTimeoutSeconds bounds check) use Write-GwClassifiedError")
def _c229():
    n = LAUNCHER_CODE.count("Write-GwClassifiedError -Message")
    return n == 7, "count=%d" % n


@check("230. Resolve-GwLiveBridgeExitCode's malformed-result path uses Write-GwClassifiedError, consistent with every other classified call site")
def _c230():
    return "Write-GwClassifiedError -Message '[M3A_BRIDGE] live_result_malformed" in RESOLVE_EXIT_HELPER_CODE, ""


@check("231. -SelfTest contains a dynamic L8 case proving Write-GwClassifiedError followed by return 2 is actually reachable -- via the SAME Resolve-GwLiveBridgeExitCode production owner, not a copy")
def _c231():
    body = SELFTEST_BODY_CODE
    calls_helper_in_invoke = "Write-GwClassifiedError -Message '[M3A_BRIDGE] selftest_l8_synthetic_classified_error'; return 2" in body
    via_owner = "Resolve-GwLiveBridgeExitCode -Invoke { Write-GwClassifiedError" in body
    return calls_helper_in_invoke and via_owner, "calls_helper_in_invoke=%s via_owner=%s" % (calls_helper_in_invoke, via_owner)


@check("232. -SelfTest contains a dynamic L9 case that calls the NO-ARGUMENT Invoke-GwChildProcessForSelfTest helper (no -ArgumentList, no live args possible) and asserts a REAL local child process's actual OS exit code is exactly 2, with the expected classified stderr text")
def _c232():
    body = SELFTEST_BODY_CODE
    spawns_child = "$l9 = Invoke-GwChildProcessForSelfTest" in body
    no_argument_list_call = "Invoke-GwChildProcessForSelfTest -ArgumentList" not in body
    checks_exit_two = "$l9.ExitCode -ne 2" in body
    checks_stderr = "$l9.StdErr" in body and "live mode requires -LiveAuthorized" in body
    return spawns_child and no_argument_list_call and checks_exit_two and checks_stderr, (
        "spawns_child=%s no_argument_list_call=%s checks_exit_two=%s checks_stderr=%s" % (
            spawns_child, no_argument_list_call, checks_exit_two, checks_stderr))


@check("233. Invoke-GwChildProcessForSelfTest runs the bridge's OWN script file via a $selfPath local captured from $PSCommandPath -- never a hardcoded developer path -- and never itself opens a serial port, starts the real backend SSH process, or makes a network call")
def _c233():
    body = CHILD_SCRIPT_HELPER_CODE
    captures_self_path = "$selfPath = $PSCommandPath" in body
    uses_self_path_in_arguments = '-File `"$selfPath`"' in body
    no_hardcoded_path = not re.search(r"[A-Za-z]:\\", body)
    hits = [s for s in ("SerialPort", "Start-GwBackendProcess", "Invoke-WebRequest", "Invoke-RestMethod", "'ssh.exe'") if s in body]
    return captures_self_path and uses_self_path_in_arguments and no_hardcoded_path and not hits, (
        "captures_self_path=%s uses_self_path_in_arguments=%s no_hardcoded_path=%s hits=%s" % (
            captures_self_path, uses_self_path_in_arguments, no_hardcoded_path, hits))


@check("234. exact-device TOKEN_STAGED forwarding (PR #5) remains unaffected by this correction -- still assigned from Confirm-GwDeviceTokenStaged, never a fabricated New-GwFrame in the live path")
def _c234():
    assigns = "$stagedFrame = Confirm-GwDeviceTokenStaged" in LIVE_BRIDGE_CODE
    no_fabricate = "New-GwFrame -Type $Script:GwMsgTokenStaged" not in LIVE_BRIDGE_CODE
    return assigns and no_fabricate, "assigns=%s no_fabricate=%s" % (assigns, no_fabricate)


@check("235. the RX backlog barrier (PR #6) remains the ONE live DiscardInBuffer call site file-wide -- unaffected by this correction")
def _c235():
    n = BRIDGE_PS1_CODE.count("$port.DiscardInBuffer()")
    return n == 1, "count=%d" % n


@check("236. -SelfTest still never opens a real serial port, starts the real backend SSH process, or makes a real network call, including the new L8/L9 dynamic fixtures")
def _c236():
    body = SELFTEST_BODY_CODE
    hits = [s for s in ("SerialPort", "Start-GwBackendProcess", "Invoke-WebRequest", "Invoke-RestMethod") if s in body]
    return not hits, "found=%s" % hits


# ===========================================================================
# PR #7 Windows PowerShell 5.1 child-process fixture correction (237-248):
# ProcessStartInfo.ArgumentList is $null on Windows PowerShell 5.1 / .NET Framework (it was only
# introduced with .NET Core/5+) -- $psi.ArgumentList.Add(...) crashed the real Windows CI runner
# with "You cannot call a method on a null-valued expression" before Process.Start() was ever
# reached. Invoke-GwChildProcessForSelfTest is now a strictly no-argument, fixed-invocation-shape
# helper built on the legacy-compatible ProcessStartInfo.Arguments string instead.
# ===========================================================================

@check("237. Invoke-GwChildProcessForSelfTest is defined exactly once file-wide")
def _c237():
    n = BRIDGE_PS1_CODE.count("function Invoke-GwChildProcessForSelfTest")
    return n == 1, "count=%d" % n


@check("238. Invoke-GwChildProcessForSelfTest contains zero ArgumentList.Add(...) calls and zero .ArgumentList references -- the API proven $null on Windows PowerShell 5.1 / .NET Framework is fully removed from this helper")
def _c238():
    body = CHILD_SCRIPT_HELPER_CODE
    n_add = body.count("ArgumentList.Add(")
    n_ref = body.count(".ArgumentList")
    return n_add == 0 and n_ref == 0, "argumentlist_add_count=%d argumentlist_ref_count=%d" % (n_add, n_ref)


@check("239. Invoke-GwChildProcessForSelfTest assigns ProcessStartInfo.Arguments (the legacy-compatible string property) exactly once")
def _c239():
    body = CHILD_SCRIPT_HELPER_CODE
    n = body.count("$psi.Arguments = ")
    return n == 1, "count=%d" % n


@check("240. Invoke-GwChildProcessForSelfTest's ProcessStartInfo.FileName remains 'powershell.exe'")
def _c240():
    body = CHILD_SCRIPT_HELPER_CODE
    return "$psi.FileName = 'powershell.exe'" in body, ""


@check("241. Invoke-GwChildProcessForSelfTest's fixed Arguments string includes -NoProfile")
def _c241():
    return "-NoProfile" in CHILD_SCRIPT_HELPER_CODE, ""


@check("242. Invoke-GwChildProcessForSelfTest's fixed Arguments string includes -NonInteractive")
def _c242():
    return "-NonInteractive" in CHILD_SCRIPT_HELPER_CODE, ""


@check("243. Invoke-GwChildProcessForSelfTest's fixed Arguments string includes -ExecutionPolicy Bypass")
def _c243():
    return "-ExecutionPolicy Bypass" in CHILD_SCRIPT_HELPER_CODE, ""


@check("244. Invoke-GwChildProcessForSelfTest's fixed Arguments string includes -File")
def _c244():
    return "-File" in CHILD_SCRIPT_HELPER_CODE, ""


@check("245. Invoke-GwChildProcessForSelfTest never passes -LiveAuthorized, -ComPort, or -SshTarget to the child -- the whole point of L9 is that the child hits the very first argument-validation gate")
def _c245():
    body = CHILD_SCRIPT_HELPER_CODE
    hits = [s for s in ("-LiveAuthorized", "-ComPort", "-SshTarget") if s in body]
    return not hits, "found=%s" % hits


@check("246. Invoke-GwChildProcessForSelfTest uses no generic shell-eval/command-runner substitute -- no cmd.exe, Invoke-Expression, or Start-Process -- this is a fixed self-path invocation, not a generic child-process command runner")
def _c246():
    body = CHILD_SCRIPT_HELPER_CODE
    hits = [s for s in ("cmd.exe", "Invoke-Expression", "Start-Process") if s in body]
    return not hits, "found=%s" % hits


@check("247. Invoke-GwChildProcessForSelfTest fails closed with a fixed, non-secret classification -- never attempting a child launch -- when $PSCommandPath is null or whitespace")
def _c247():
    body = CHILD_SCRIPT_HELPER_CODE
    has_guard = "[string]::IsNullOrWhiteSpace($selfPath)" in body
    fails_before_launch = body.index("IsNullOrWhiteSpace($selfPath)") < body.index("[System.Diagnostics.Process]::Start($psi)")
    fixed_message = "selftest_l9_self_path_unavailable" in body
    return has_guard and fails_before_launch and fixed_message, (
        "has_guard=%s fails_before_launch=%s fixed_message=%s" % (has_guard, fails_before_launch, fixed_message))


@check("248. Invoke-GwChildProcessForSelfTest guards against a $null Process.Start() result (defense-in-depth, not the proven root cause) before ever touching StandardOutput/StandardError, failing closed with a fixed non-secret classification instead of a null dereference")
def _c248():
    body = CHILD_SCRIPT_HELPER_CODE
    guard_idx = body.find("$null -eq $proc")
    start_idx = body.find("[System.Diagnostics.Process]::Start($psi)")
    read_idx = body.find(".StandardOutput.ReadToEnd()")
    ordered = start_idx != -1 and guard_idx != -1 and read_idx != -1 and start_idx < guard_idx < read_idx
    fixed_message = "selftest_l9_child_process_start_failed" in body
    return ordered and fixed_message, "ordered=%s fixed_message=%s" % (ordered, fixed_message)


# ===========================================================================
# PR #7 L9 literal stderr assertion correction (249-254): PowerShell -like/-notlike treats a
# `[...]` run as a wildcard character class, so `-notlike '*[M3A_BRIDGE] ...*'` never matched the
# literal bracketed `[M3A_BRIDGE]` prefix -- hermetically reproduced (BROKEN_LIKE=False,
# LITERAL_CONTAINS=True for the identical string). L9 now uses String.Contains(), which has no
# wildcard/regex semantics, against a local constant byte-identical to the production entrypoint's
# actual classified message.
# ===========================================================================

@check("249. L9's expected-classified-message assertion no longer uses -like/-notlike -- the wildcard operator whose `[...]` character-class semantics caused the proven false negative")
def _c249():
    body = SELFTEST_BODY_CODE
    l9_section = body[body.index("$l9 = Invoke-GwChildProcessForSelfTest"):]
    has_like = "-notlike" in l9_section or " -like " in l9_section
    return not has_like, "has_like_or_notlike=%s" % has_like


@check("250. L9's expected-classified-message assertion uses literal String.Contains() containment")
def _c250():
    body = SELFTEST_BODY_CODE
    return "$l9.StdErr.Contains($l9ExpectedClassifiedMessage)" in body, ""


@check("251. L9's expected classified message local constant is byte-identical to the production entrypoint's actual Write-GwClassifiedError -LiveAuthorized message")
def _c251():
    l9_literal = "$l9ExpectedClassifiedMessage = '[M3A_BRIDGE] live mode requires -LiveAuthorized'" in SELFTEST_BODY_CODE
    production_literal = "Write-GwClassifiedError -Message '[M3A_BRIDGE] live mode requires -LiveAuthorized'" in LAUNCHER_CODE
    return l9_literal and production_literal, "l9_literal=%s production_literal=%s" % (l9_literal, production_literal)


@check("252. L9's child ExitCode assertion is unchanged -- still asserts exactly 2")
def _c252():
    return "if ($l9.ExitCode -ne 2) { $failures.Add('live_entrypoint_child_exit_code_not_two') }" in SELFTEST_BODY_CODE, ""


@check("253. L9's child stdout-empty assertion is unchanged")
def _c253():
    return "live_entrypoint_child_unexpected_stdout" in SELFTEST_BODY_CODE, ""


@check("254. L9's child transport-activity assertion is unchanged")
def _c254():
    return "live_entrypoint_child_unexpected_transport_activity_observed" in SELFTEST_BODY_CODE, ""


# ===========================================================================
# M3B-TIMING correction (255-264): the F7 post-COMMIT, diagnostics-only voice-ready observation
# window previously reused the generic -ProtocolTimeoutSeconds budget (max 15s), but the firmware's
# own legal post-COMMIT chain (Wi-Fi IP wait up to 30s + HTTPS session up to 10s + voice READY wait
# up to 20s = up to 60s) can legitimately exceed that -- a proven false-negative observation window,
# not evidence of an audio/device fault. F7 now uses its own dedicated -VoiceReadyTimeoutSeconds
# budget (default 75, bounded 65..120), fully decoupled from the pre-COMMIT protocol timeout.
# ===========================================================================

@check("255. the bridge declares a -VoiceReadyTimeoutSeconds parameter with default 75")
def _c255():
    return "[int]$VoiceReadyTimeoutSeconds = 75" in BRIDGE_PS1_RAW, ""


@check("256. -VoiceReadyTimeoutSeconds validation rejects values below 65")
def _c256():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwVoiceReadyTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    return "-ge 65" in body, ""


@check("257. -VoiceReadyTimeoutSeconds validation rejects values above 120")
def _c257():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwVoiceReadyTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    return "-le 120" in body, ""


@check("258. the F7 post-COMMIT observation deadline uses -VoiceReadyTimeoutSeconds")
def _c258():
    return "$deadline = (Get-Date).AddSeconds($VoiceReadyTimeoutSeconds)" in LIVE_BRIDGE_CODE, ""


@check("259. the F7 post-COMMIT observation block no longer references -ProtocolTimeoutSeconds anywhere -- fully decoupled from the pre-COMMIT protocol budget")
def _c259():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1 and f7_start < finally_idx
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    return "ProtocolTimeoutSeconds" not in f7_body, ""


@check("260. -ProtocolTimeoutSeconds still exists and its bound (1..15) is unchanged -- not widened to paper over the F7 false negative")
def _c260():
    body = _extract_c_function(BRIDGE_PS1_RAW, "function Test-GwProtocolTimeoutSecondsValid", "function Test-GwByteArrayEqual")
    return "-ge 1 -and $Seconds -le 15" in body, ""


@check("261. the [V2_WATCHER_PROVISION] voice: ready literal is unchanged and [M3A_BRIDGE] decision: commit remains structurally before the F7 observation block")
def _c261():
    marker_ok = "'[V2_WATCHER_PROVISION] voice: ready'" in LIVE_BRIDGE_CODE
    commit_idx = LIVE_BRIDGE_CODE.find("Write-Host '[M3A_BRIDGE] decision: commit'")
    f7_idx = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    ordered = commit_idx != -1 and f7_idx != -1 and commit_idx < f7_idx
    return marker_ok and ordered, "marker_ok=%s commit_idx=%d f7_idx=%d" % (marker_ok, commit_idx, f7_idx)


@check("262. the F7 observation window remains diagnostics-only and non-fatal after COMMIT -- both the READY-observed and timeout branches share one `return 0`, never `return 2`, and never emit PROVISION_ABORT")
def _c262():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    has_true = "Write-Host '[M3A_BRIDGE] device_ready: true'" in f7_body
    has_timeout = "Write-Host '[M3A_BRIDGE] device_ready: timeout'" in f7_body
    has_return_zero = "return 0" in f7_body
    no_return_two = "return 2" not in f7_body
    no_abort = "GwMsgProvisionAbort" not in f7_body
    return has_true and has_timeout and has_return_zero and no_return_two and no_abort, (
        "has_true=%s has_timeout=%s has_return_zero=%s no_return_two=%s no_abort=%s" % (
            has_true, has_timeout, has_return_zero, no_return_two, no_abort))


@check("263. firmware GW_IP_WAIT_MS remains 30000 -- unaffected by this bridge-only correction (READ ONLY target)")
def _c263():
    return "GW_IP_WAIT_MS            30000" in PROVISION_C_RAW, ""


@check("264. firmware GW_VOICE_READY_TIMEOUT_MS remains 20000 -- unaffected by this bridge-only correction (READ ONLY target)")
def _c264():
    return "GW_VOICE_READY_TIMEOUT_MS 20000" in PROVISION_C_RAW, ""


# ===========================================================================
# M3B safe post-COMMIT diagnostics correction (265-286): the F7 observer previously discarded every safe
# firmware terminal/WSS classification line the physical attempt #1 root-cause audit proved was needed but
# NOT_RECOVERABLE. F7 now additionally recognizes a FIXED allowlist of already-existing safe firmware markers
# and surfaces them as this bridge's own normalized `[M3A_BRIDGE] voice_diag: ...` strings -- never a raw
# serial echo, never persisted, never able to influence device_ready/exit-code/COMMIT/ABORT semantics.
# ===========================================================================

SAFE_DIAG_PAYLOAD_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Resolve-GwSafeDiagnosticPayload", "function Resolve-GwEspIdfDiagnosticPayload")
SAFE_DIAG_ENVELOPE_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Resolve-GwEspIdfDiagnosticPayload", "function Resolve-GwSafeFirmwareDiagnosticLine")
SAFE_DIAG_HELPER_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Resolve-GwSafeFirmwareDiagnosticLine", "function New-GwSafeFirmwareDiagnosticState")
SAFE_DIAG_STATE_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function New-GwSafeFirmwareDiagnosticState", "function Push-GwSafeFirmwareDiagnosticByte")
SAFE_DIAG_PUSH_CODE = _extract_c_function(
    BRIDGE_PS1_CODE, "function Push-GwSafeFirmwareDiagnosticByte", "function Wait-GwBridgeReady")


@check("265. GwSafeDiagnosticLineMaxBytes exists and equals 256")
def _c265():
    return "$Script:GwSafeDiagnosticLineMaxBytes = 256" in BRIDGE_PS1_RAW, ""


@check("266. Resolve-GwSafeFirmwareDiagnosticLine exists exactly once")
def _c266():
    n = BRIDGE_PS1_CODE.count("function Resolve-GwSafeFirmwareDiagnosticLine")
    return n == 1, "count=%d" % n


@check("267. New-GwSafeFirmwareDiagnosticState exists exactly once")
def _c267():
    n = BRIDGE_PS1_CODE.count("function New-GwSafeFirmwareDiagnosticState")
    return n == 1, "count=%d" % n


@check("268. Push-GwSafeFirmwareDiagnosticByte exists exactly once")
def _c268():
    n = BRIDGE_PS1_CODE.count("function Push-GwSafeFirmwareDiagnosticByte")
    return n == 1, "count=%d" % n


@check("269. all eight normalized `[M3A_BRIDGE] voice_diag: ...` event shapes are present")
def _c269():
    body = BRIDGE_PS1_CODE
    required = [
        "[M3A_BRIDGE] voice_diag: session_http_200",
        "[M3A_BRIDGE] voice_diag: session_ready setup_bytes=",
        "[M3A_BRIDGE] voice_diag: ws_connected",
        "[M3A_BRIDGE] voice_diag: ws_setup_sent",
        "[M3A_BRIDGE] voice_diag: ws_ready",
        "[M3A_BRIDGE] voice_diag: ws_error type=",
        "[M3A_BRIDGE] voice_diag: ws_closed",
        "[M3A_BRIDGE] voice_diag: terminal_code=",
    ]
    missing = [s for s in required if s not in body]
    return not missing, "missing=%s" % missing


@check("270. the terminal-code diagnostic parser is bounded to 0..16 -- owned by the single canonical Resolve-GwSafeDiagnosticPayload allowlist, reused by both the bare and ESP-IDF envelope acceptance paths")
def _c270():
    body = SAFE_DIAG_PAYLOAD_CODE
    return "$code -ge 0 -and $code -le 16" in body, ""


@check("271. the setup_bytes diagnostic parser is bounded to 1..32767 -- owned by the single canonical Resolve-GwSafeDiagnosticPayload allowlist, reused by both the bare and ESP-IDF envelope acceptance paths")
def _c271():
    body = SAFE_DIAG_PAYLOAD_CODE
    return "$setupBytes -ge 1 -and $setupBytes -le 32767" in body, ""


@check("272. F7 constructs exactly one diagnostic state before its observation loop")
def _c272():
    body = LIVE_BRIDGE_CODE
    n = body.count("New-GwSafeFirmwareDiagnosticState")
    idx_state = body.find("$diagnosticState = New-GwSafeFirmwareDiagnosticState")
    idx_loop = body.find("while ((Get-Date) -lt $deadline)")
    ordered = idx_state != -1 and idx_loop != -1 and idx_state < idx_loop
    return n == 1 and ordered, "count=%d ordered=%s" % (n, ordered)


@check("273. F7 feeds the same already-read UART byte to the diagnostic byte helper -- never a second serial read")
def _c273():
    body = LIVE_BRIDGE_CODE
    return "Push-GwSafeFirmwareDiagnosticByte -State $diagnosticState -Byte ([byte]$b)" in body, ""


@check("274. F7 prints only the normalized helper return value via Write-Host -- never a raw serial line, never Write-Output/Write-Error for diagnostics")
def _c274():
    body = LIVE_BRIDGE_CODE
    prints_normalized = "Write-Host $safeDiagnostic" in body
    no_raw_echo = "Write-Host $b" not in body and "Write-Host $line" not in body and "Write-Host $rawLine" not in body
    return prints_normalized and no_raw_echo, "prints_normalized=%s no_raw_echo=%s" % (prints_normalized, no_raw_echo)


@check("275. F7 still uses the exact existing voice-ready marker, unchanged by the diagnostics correction")
def _c275():
    return "'[V2_WATCHER_PROVISION] voice: ready'" in LIVE_BRIDGE_CODE, ""


@check("276. F7 still uses -VoiceReadyTimeoutSeconds for its deadline, unchanged by the diagnostics correction")
def _c276():
    return "$deadline = (Get-Date).AddSeconds($VoiceReadyTimeoutSeconds)" in LIVE_BRIDGE_CODE, ""


@check("277. F7's post-COMMIT observation block still contains no -ProtocolTimeoutSeconds reference")
def _c277():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1 and f7_start < finally_idx
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    return "ProtocolTimeoutSeconds" not in f7_body, ""


@check("278. F7 still emits both device_ready true and device_ready timeout, unchanged by the diagnostics correction")
def _c278():
    has_true = "Write-Host '[M3A_BRIDGE] device_ready: true'" in LIVE_BRIDGE_CODE
    has_timeout = "Write-Host '[M3A_BRIDGE] device_ready: timeout'" in LIVE_BRIDGE_CODE
    return has_true and has_timeout, "has_true=%s has_timeout=%s" % (has_true, has_timeout)


@check("279. F7 still shares one `return 0` after the observation loop and contains no `return 2` -- diagnostics cannot turn a successful COMMIT into a failure")
def _c279():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    return "return 0" in f7_body and "return 2" not in f7_body, ""


@check("280. F7 contains no GwMsgProvisionAbort reference -- diagnostics cannot originate a bridge ABORT")
def _c280():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    return "GwMsgProvisionAbort" not in f7_body, ""


@check("281. the bridge live exit-code contract remains exactly {0, 2}, unchanged by the diagnostics correction")
def _c281():
    return "$Script:GwLiveBridgeExitCodes = @(0, 2)" in BRIDGE_PS1_RAW, ""


@check("282. firmware GW_VOICE_READY_TIMEOUT_MS remains 20000 -- READ ONLY target, unaffected by this bridge-only correction")
def _c282():
    return "GW_VOICE_READY_TIMEOUT_MS 20000" in PROVISION_C_RAW, ""


@check("283. firmware terminal log format remains `[V2_WATCHER_PROVISION] terminal: code=%d` -- READ ONLY target, the exact source shape the new parser consumes")
def _c283():
    return '"[V2_WATCHER_PROVISION] terminal: code=%d"' in PROVISION_C_RAW, ""


@check("284. firmware WSS safe-log source strings remain the canonical shapes the new parser consumes -- READ ONLY target")
def _c284():
    voice_c_path = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_voice.c")
    voice_c_raw = _read(voice_c_path) if os.path.isfile(voice_c_path) else ""
    required = [
        '"[V2_WATCHER_PROVISION] session: http_200"',
        '"[V2_WATCHER_VOICE] session_ready: setup_bytes=%d"',
        '"[V2_WATCHER_VOICE] ws_state: connected"',
        '"[V2_WATCHER_VOICE] ws_state: setup_sent"',
        '"[V2_WATCHER_VOICE] ws_state: ready"',
        '"[V2_WATCHER_VOICE] ws_error: type=%d status=%d"',
        '"[V2_WATCHER_VOICE] ws_state: closed"',
    ]
    combined = PROVISION_C_RAW + voice_c_raw
    missing = [s for s in required if s not in combined]
    return not missing, "missing=%s" % missing


@check("285. no new file path or persistence primitive is introduced anywhere in the F7 diagnostics addition")
def _c285():
    body = SAFE_DIAG_HELPER_CODE + SAFE_DIAG_STATE_CODE + SAFE_DIAG_PUSH_CODE
    hits = [s for s in ("New-Item", "Out-File", "Set-Content", "Add-Content", "[System.IO.File]", "Export-") if s in body]
    return not hits, "found=%s" % hits


@check("286. the existing Windows -SelfTest includes overflow, injection, unknown-line, and CRLF safe-diagnostic cases")
def _c286():
    body = SELFTEST_BODY_CODE
    required = [
        "safe_diag_overflow_suppressed_until_newline",
        "safe_diag_recovery_after_overflow_newline",
        "safe_diag_crlf_single_emit",
        "safe_diag_suffix_injection_rejected",
        "safe_diag_prefix_injection_rejected",
        "safe_diag_unknown_line_suppressed",
        "safe_diag_token_like_line_suppressed",
    ]
    missing = [s for s in required if s not in body]
    return not missing, "missing=%s" % missing


# ===========================================================================
# M3B PR#8 ESP-IDF diagnostic envelope correction (287-298): the prior safe-diagnostics correction's parser
# only recognized a bare payload line, but ESP_LOGI/ESP_LOGW render "<I|W> (<timestamp>) <tag>: <payload>"
# (plus an optional bounded ANSI SGR wrapper) on the real physical UART -- a proven false-green coverage gap
# (290/290 + Windows SelfTest PASS while emitting zero voice_diag lines on the real device). The parser now
# additionally recognizes that exact envelope via Resolve-GwEspIdfDiagnosticPayload, reusing the SAME
# Resolve-GwSafeDiagnosticPayload allowlist owner the bare path already used -- never a parallel parser.
# ===========================================================================

@check("287. realistic ESP-IDF envelope SelfTest fixtures exist for all eight canonical diagnostic markers")
def _c287():
    body = SELFTEST_BODY_CODE
    required = [
        "safe_diag_esp_envelope_http_200", "safe_diag_esp_envelope_terminal",
        "safe_diag_esp_envelope_session_ready", "safe_diag_esp_envelope_ws_connected",
        "safe_diag_esp_envelope_ws_setup_sent", "safe_diag_esp_envelope_ws_ready",
        "safe_diag_esp_envelope_ws_error", "safe_diag_esp_envelope_ws_closed",
    ]
    missing = [s for s in required if s not in body]
    return not missing, "missing=%s" % missing


@check("288. an ANSI-wrapped ESP-IDF envelope fixture exists for both Info and Warning severities, using distinct SGR prefixes -- not one hardcoded color")
def _c288():
    body = SELFTEST_BODY_CODE
    has_info = "safe_diag_esp_envelope_ansi" in body and "0;32m" in body
    has_warn = "safe_diag_esp_envelope_ansi_warn" in body and "0;33m" in body
    return has_info and has_warn, "has_info=%s has_warn=%s" % (has_info, has_warn)


@check("289. a wrong-tag rejection fixture exists")
def _c289():
    return "safe_diag_wrong_tag_rejected" in SELFTEST_BODY_CODE, ""


@check("290. a wrong-severity rejection fixture exists")
def _c290():
    return "safe_diag_wrong_severity_rejected" in SELFTEST_BODY_CODE, ""


@check("291. a wrong-timestamp-syntax rejection fixture exists")
def _c291():
    return "safe_diag_wrong_timestamp_rejected" in SELFTEST_BODY_CODE, ""


@check("292. an embedded-ANSI-inside-payload rejection fixture exists")
def _c292():
    return "safe_diag_embedded_ansi_rejected" in SELFTEST_BODY_CODE, ""


@check("293. the ESP-IDF envelope parser requires an exact V2_WATCHER_PROVISION or V2_WATCHER_VOICE tag -- no arbitrary tag name")
def _c293():
    body = SAFE_DIAG_ENVELOPE_CODE
    return "(V2_WATCHER_PROVISION|V2_WATCHER_VOICE)" in body, ""


@check("294. the ESP-IDF envelope parser distinguishes I (Info) vs W (Warning) severity and cross-checks it against the payload's own expected severity -- a correct payload under the wrong severity is rejected")
def _c294():
    envelope_severity_capture = "([IW]) \\(" in SAFE_DIAG_ENVELOPE_CODE
    orchestrator_checks_severity = "$envelope.Severity -cne $payloadMatch.ExpectedSeverity" in SAFE_DIAG_HELPER_CODE
    payload_owner_sets_severity = "ExpectedSeverity = 'W'" in SAFE_DIAG_PAYLOAD_CODE and "ExpectedSeverity = 'I'" in SAFE_DIAG_PAYLOAD_CODE
    return envelope_severity_capture and orchestrator_checks_severity and payload_owner_sets_severity, (
        "envelope_severity_capture=%s orchestrator_checks_severity=%s payload_owner_sets_severity=%s" % (
            envelope_severity_capture, orchestrator_checks_severity, payload_owner_sets_severity))


@check("295. Resolve-GwSafeFirmwareDiagnosticLine still never returns/echoes the raw input line -- every return path is either $null or a fixed normalized string from the single canonical Resolve-GwSafeDiagnosticPayload owner")
def _c295():
    body = SAFE_DIAG_HELPER_CODE
    returns_raw_line = "return $Line" in body or "return $envelope" in body
    only_normalized_or_null = "return $bareMatch.Normalized" in body and "return $payloadMatch.Normalized" in body
    return not returns_raw_line and only_normalized_or_null, (
        "returns_raw_line=%s only_normalized_or_null=%s" % (returns_raw_line, only_normalized_or_null))


@check("296. F7 remains a single-reader, same-byte observer -- the diagnostic accumulator is fed the exact same already-read $b as the ready-marker scanner, never a second serial read")
def _c296():
    f7_start = LIVE_BRIDGE_CODE.find("$marker = [System.Text.Encoding]::ASCII.GetBytes('[V2_WATCHER_PROVISION] voice: ready')")
    finally_idx = LIVE_BRIDGE_CODE.find("} finally {")
    assert f7_start != -1 and finally_idx != -1
    f7_body = LIVE_BRIDGE_CODE[f7_start:finally_idx]
    n_readbyte = f7_body.count("$port.ReadByte()")
    feeds_same_byte = "Push-GwSafeFirmwareDiagnosticByte -State $diagnosticState -Byte ([byte]$b)" in f7_body
    return n_readbyte == 1 and feeds_same_byte, "n_readbyte=%d feeds_same_byte=%s" % (n_readbyte, feeds_same_byte)


@check("297. the bridge live exit-code contract remains exactly {0, 2}, unchanged by the ESP-IDF envelope correction")
def _c297():
    return "$Script:GwLiveBridgeExitCodes = @(0, 2)" in BRIDGE_PS1_RAW, ""


@check("298. firmware source remains READ ONLY -- unaffected by this bridge-only ESP-IDF envelope correction (both C/H files and canonical log strings unchanged)")
def _c298():
    voice_c_path = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_watcher_voice.c")
    voice_c_raw = _read(voice_c_path) if os.path.isfile(voice_c_path) else ""
    required = [
        '"[V2_WATCHER_PROVISION] session: http_200"',
        '"[V2_WATCHER_PROVISION] terminal: code=%d"',
        '"[V2_WATCHER_VOICE] session_ready: setup_bytes=%d"',
        '"[V2_WATCHER_VOICE] ws_state: connected"',
        '"[V2_WATCHER_VOICE] ws_state: setup_sent"',
        '"[V2_WATCHER_VOICE] ws_state: ready"',
        '"[V2_WATCHER_VOICE] ws_error: type=%d status=%d"',
        '"[V2_WATCHER_VOICE] ws_state: closed"',
    ]
    combined = PROVISION_C_RAW + voice_c_raw
    missing = [s for s in required if s not in combined]
    tag_ok = 'static const char *TAG = "V2_WATCHER_PROVISION"' in PROVISION_C_RAW and 'static const char *TAG = "V2_WATCHER_VOICE"' in voice_c_raw
    return not missing and tag_ok, "missing=%s tag_ok=%s" % (missing, tag_ok)


if __name__ == "__main__":
    sys.exit(main())
