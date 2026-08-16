#!/usr/bin/env python3
"""GPTNiX Watcher QR pairing foundation — source/architecture fitness test.

Python standard library only, no pip dependency. This is a STATIC SOURCE
proof, not a runtime/physical proof: it never builds, flashes, or executes
firmware. It exits non-zero if any invariant listed below is violated.

Note on invariants 22-24 ("file X remains unchanged"): the CI checkout this
test runs under uses `fetch-depth: 1` (see .github/workflows/
gptnix-firmware-build.yml), so no git history is available to diff against a
prior commit. These three invariants are therefore verified as STRUCTURAL
PRESENCE checks (the specific markers that would be missing/broken if the
canonical owner had been modified or removed) rather than a content diff.
"""
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FACTORY_DIR = os.path.dirname(SCRIPT_DIR)  # .../examples/factory_firmware
REPO_ROOT = os.path.dirname(os.path.dirname(FACTORY_DIR))  # repo root

KCONFIG = os.path.join(FACTORY_DIR, "main", "Kconfig.projbuild")
IDF_COMPONENT_YML = os.path.join(FACTORY_DIR, "main", "idf_component.yml")
APP_C = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_qr_pair.c")
APP_H = os.path.join(FACTORY_DIR, "main", "app", "app_gptnix_qr_pair.h")
CONTRACT_MD = os.path.join(FACTORY_DIR, "docs", "GPTNIX_QR_PAIRING_CONTRACT_V1.md")
SDKCONFIG_DEFAULTS = os.path.join(FACTORY_DIR, "sdkconfig.defaults")
CMAKELISTS = os.path.join(FACTORY_DIR, "main", "CMakeLists.txt")
TF_CAMERA = os.path.join(FACTORY_DIR, "main", "task_flow_module", "tf_module_ai_camera.c")
SSCMA_OPS_C = os.path.join(REPO_ROOT, "components", "sscma_client", "src", "sscma_client_ops.c")

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


# 1-3. Kconfig kill switch
@check("1. exactly one `config GPTNIX_QR_PAIRING` block")
def _c1():
    text = _read(KCONFIG)
    matches = re.findall(r"^\s*config\s+GPTNIX_QR_PAIRING\s*$", text, re.MULTILINE)
    return len(matches) == 1, "found %d" % len(matches)


@check("2. GPTNIX_QR_PAIRING block has default n")
def _c2():
    text = _read(KCONFIG)
    m = re.search(r"config\s+GPTNIX_QR_PAIRING\s*\n(.*?)(?=\n\s*config\s|\nendmenu)", text, re.DOTALL)
    if not m:
        return False, "block not found"
    block = m.group(1)
    return bool(re.search(r"^\s*default\s+n\s*$", block, re.MULTILINE)), block.strip()[:80]


@check("3. no `config CONFIG_GPTNIX_QR_PAIRING` (wrong symbol name) exists anywhere")
def _c3():
    text = _read(KCONFIG)
    return "config CONFIG_GPTNIX_QR_PAIRING" not in text, ""


# 4. quirc dependency exactly once
@check("4. espressif/quirc ^1.2.0 declared exactly once in factory idf_component.yml")
def _c4():
    text = _read(IDF_COMPONENT_YML)
    matches = re.findall(r"espressif/quirc:\s*[\"']?\^1\.2\.0[\"']?", text)
    return len(matches) == 1, "found %d" % len(matches)


# 5. canonical files exist
@check("5. canonical .c/.h/contract/fitness files exist")
def _c5():
    missing = [p for p in (APP_C, APP_H, CONTRACT_MD, os.path.abspath(__file__)) if not os.path.isfile(p)]
    return not missing, "missing: %s" % missing


# 6-11. forbidden calls in the new source
@check("6. no sscma_client_register_callback in app_gptnix_qr_pair.c")
def _c6():
    return "sscma_client_register_callback" not in _read(APP_C), ""


@check("7. no bsp_sscma_client_init in app_gptnix_qr_pair.c")
def _c7():
    return "bsp_sscma_client_init" not in _read(APP_C), ""


@check("8. no sscma_client_sample/invoke/set_sensor in app_gptnix_qr_pair.c")
def _c8():
    text = _read(APP_C)
    hits = [s for s in ("sscma_client_sample", "sscma_client_invoke", "sscma_client_set_sensor") if s in text]
    return not hits, "found: %s" % hits


@check("9. no esp_http_client in app_gptnix_qr_pair.c")
def _c9():
    return "esp_http_client" not in _read(APP_C), ""


@check("10. no storage_write/storage_read/nvs_ API use in app_gptnix_qr_pair.c")
def _c10():
    text = _read(APP_C)
    hits = [s for s in ("storage_write", "storage_read", "nvs_") if s in text]
    return not hits, "found: %s" % hits


@check("11. no BLE API use in app_gptnix_qr_pair.c")
def _c11():
    text = _read(APP_C).lower()
    hits = [s for s in ("ble_gap", "ble_gatt", "esp_ble", "nimble") if s in text]
    return not hits, "found: %s" % hits


@check("12. no Firebase identitytoolkit/securetoken URL literal in app_gptnix_qr_pair.c")
def _c12():
    text = _read(APP_C).lower()
    hits = [s for s in ("identitytoolkit", "securetoken") if s in text]
    return not hits, "found: %s" % hits


@check("13. no Gemini API key / Google Live endpoint literal in app_gptnix_qr_pair.c")
def _c13():
    text = _read(APP_C)
    hits = [s for s in ("GEMINI_API_KEY", "generativelanguage.googleapis.com", "BidiGenerateContent") if s in text]
    return not hits, "found: %s" % hits


@check("14. no uncontrolled printf in app_gptnix_qr_pair.c")
def _c14():
    text = _read(APP_C)
    return re.search(r"(?<![A-Za-z0-9_])printf\s*\(", text) is None, ""


@check("15. no ESP_LOG line formats %s (raw QR/pairing fields must never be logged)")
def _c15():
    text = _read(APP_C)
    offending = [ln for ln in text.splitlines() if "ESP_LOG" in ln and "%s" in ln]
    return not offending, "lines: %s" % offending


# 16. header exposes exact canonical API
@check("16. header exposes all exact canonical API symbols")
def _c16():
    text = _read(APP_H)
    required = [
        "GPTNIX_QR_PAIR_RESULT_OK",
        "GPTNIX_QR_PAIR_RESULT_DISABLED",
        "GPTNIX_QR_PAIR_RESULT_NOT_INITIALIZED",
        "GPTNIX_QR_PAIR_RESULT_INVALID_ARGUMENT",
        "GPTNIX_QR_PAIR_RESULT_IMAGE_TOO_LARGE",
        "GPTNIX_QR_PAIR_RESULT_IMAGE_DECODE_FAILED",
        "GPTNIX_QR_PAIR_RESULT_UNSUPPORTED_DIMENSIONS",
        "GPTNIX_QR_PAIR_RESULT_NO_CODE",
        "GPTNIX_QR_PAIR_RESULT_AMBIGUOUS",
        "GPTNIX_QR_PAIR_RESULT_QR_DECODE_FAILED",
        "GPTNIX_QR_PAIR_RESULT_INVALID_PAYLOAD",
        "GPTNIX_QR_PAIR_RESULT_NO_MEMORY",
        "gptnix_qr_pair_result_t",
        "gptnix_qr_pair_payload_t",
        "pairing_id[129]",
        "pairing_value[257]",
        "app_gptnix_qr_pair_init",
        "app_gptnix_qr_pair_deinit",
        "app_gptnix_qr_pair_decode_base64_jpeg",
        "app_gptnix_qr_pair_payload_clear",
    ]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 17. fixed memory bounds present
@check("17. source uses 240x240 / 48KiB JPEG / 65536 base64 / 512 payload bounds")
def _c17():
    text = _read(APP_C)
    required = ["(240)", "49152", "65536", "(512)"]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 18. JPEG dimension validated before jpeg_dec_process
@check("18. JPEG width/height validated before jpeg_dec_process")
def _c18():
    text = _read(APP_C)
    dim_check_idx = text.find("jpeg_info.width")
    process_idx = text.find("jpeg_dec_process(")
    if dim_check_idx == -1 or process_idx == -1:
        return False, "dim_check_idx=%d process_idx=%d" % (dim_check_idx, process_idx)
    return dim_check_idx < process_idx, "dim_check@%d < process@%d" % (dim_check_idx, process_idx)


# 19. mbedtls_platform_zeroize used for secret-bearing output clear
@check("19. mbedtls_platform_zeroize used for payload-clear and decode-path secret cleanup")
def _c19():
    text = _read(APP_C)
    has_payload_clear_zeroize = "mbedtls_platform_zeroize(payload" in text
    has_decode_path_zeroize = "mbedtls_platform_zeroize(&data" in text
    ok = has_payload_clear_zeroize and has_decode_path_zeroize
    return ok, "payload_clear=%s decode_path=%s" % (has_payload_clear_zeroize, has_decode_path_zeroize)


# 20. contract content
@check("20. contract declares exact envelope fields + RAM-only/no-PoP-canary invariants")
def _c20():
    text = _read(CONTRACT_MD)
    required = ["schemaVersion", "pairingId", "pairingValue", "RAM only", "PoP", "NVS"]
    missing = [s for s in required if s not in text]
    return not missing, "missing: %s" % missing


# 21. tracked sdkconfig.defaults does not enable the flag
@check("21. tracked sdkconfig.defaults does not set CONFIG_GPTNIX_QR_PAIRING=y")
def _c21():
    if not os.path.isfile(SDKCONFIG_DEFAULTS):
        return True, "sdkconfig.defaults absent (nothing to violate)"
    text = _read(SDKCONFIG_DEFAULTS)
    return "CONFIG_GPTNIX_QR_PAIRING=y" not in text, ""


# 22. factory CMakeLists structural presence (see module docstring: no git history in CI)
@check("22. factory main/CMakeLists.txt still auto-globs main/app/*.c")
def _c22():
    text = _read(CMAKELISTS)
    ok = ("GLOB_RECURSE APP_SRCS" in text) and ("APP_DIR" in text)
    return ok, ""


# 23. tf_module_ai_camera.c structural presence
@check("23. tf_module_ai_camera.c still registers the canonical SSCMA callback")
def _c23():
    text = _read(TF_CAMERA)
    return "sscma_client_register_callback" in text, ""


# 24. components/sscma_client structural presence
@check("24. components/sscma_client/src/sscma_client_ops.c still defines sscma_client_register_callback")
def _c24():
    if not os.path.isfile(SSCMA_OPS_C):
        return False, "file missing"
    text = _read(SSCMA_OPS_C)
    return "esp_err_t sscma_client_register_callback" in text, ""


def _disabled_impl_region(text):
    m = re.search(
        r"#else\s*/\*\s*!CONFIG_GPTNIX_QR_PAIRING\s*\*/(.*?)#endif\s*/\*\s*CONFIG_GPTNIX_QR_PAIRING\s*\*/",
        text, re.DOTALL,
    )
    return m.group(1) if m else ""


# 25. disabled implementation clears non-NULL out_payload
@check("25. compile-time-disabled decode clears non-NULL out_payload before returning DISABLED")
def _c25():
    region = _disabled_impl_region(_read(APP_C))
    has_clear_call = "app_gptnix_qr_pair_payload_clear(out_payload)" in region
    has_disabled_return = "GPTNIX_QR_PAIR_RESULT_DISABLED" in region
    clear_idx = region.find("app_gptnix_qr_pair_payload_clear(out_payload)")
    disabled_idx = region.find("return GPTNIX_QR_PAIR_RESULT_DISABLED")
    ordered = has_clear_call and has_disabled_return and 0 <= clear_idx < disabled_idx
    return ordered, "clear_present=%s disabled_present=%s order_ok=%s" % (has_clear_call, has_disabled_return, ordered)


# 26. embedded-NUL rejection before JSON parse
@check("26. embedded-NUL in data.payload is rejected before cJSON parsing")
def _c26():
    text = _read(APP_C)
    memchr_idx = text.find("memchr(data.payload")
    parse_idx = text.find("cJSON_ParseWithLengthOpts(")
    if memchr_idx == -1 or parse_idx == -1:
        return False, "memchr_idx=%d parse_idx=%d" % (memchr_idx, parse_idx)
    return memchr_idx < parse_idx, "memchr@%d < parse@%d" % (memchr_idx, parse_idx)


# 27. cJSON_ParseWithLengthOpts used for the pairing envelope
@check("27. cJSON_ParseWithLengthOpts is used for the pairing envelope")
def _c27():
    return "cJSON_ParseWithLengthOpts(qr_text" in _read(APP_C), ""


# 28. plain cJSON_Parse(qr_text) no longer used
@check("28. plain cJSON_Parse(qr_text) is no longer used")
def _c28():
    return "cJSON_Parse(qr_text)" not in _read(APP_C), ""


# 29. module-owned JPEG scratch is zeroized
@check("29. module-owned JPEG scratch (s_jpeg_buf) is zeroized")
def _c29():
    return "mbedtls_platform_zeroize(s_jpeg_buf" in _read(APP_C), ""


# 30. module-owned RGB565 scratch is zeroized
@check("30. module-owned RGB565 scratch (s_rgb565_buf) is zeroized")
def _c30():
    return "mbedtls_platform_zeroize(s_rgb565_buf" in _read(APP_C), ""


# 31. quirc grayscale frame scratch is zeroized
@check("31. quirc grayscale frame scratch (qbuf) is zeroized")
def _c31():
    return "mbedtls_platform_zeroize(qbuf," in _read(APP_C), ""


# 32. deinit/unwind zeroizes image scratch before free
@check("32. s_unwind_partial_init zeroizes JPEG/RGB565 scratch before freeing each")
def _c32():
    text = _read(APP_C)
    m = re.search(
        r"static void s_unwind_partial_init\(.*?\n\}\n", text, re.DOTALL,
    )
    if not m:
        return False, "s_unwind_partial_init body not found"
    body = m.group(0)
    rgb_zero_idx = body.find("mbedtls_platform_zeroize(s_rgb565_buf")
    rgb_free_idx = body.find("free(s_rgb565_buf)")
    jpeg_zero_idx = body.find("mbedtls_platform_zeroize(s_jpeg_buf")
    jpeg_free_idx = body.find("free(s_jpeg_buf)")
    ok = (
        rgb_zero_idx != -1 and rgb_free_idx != -1 and rgb_zero_idx < rgb_free_idx
        and jpeg_zero_idx != -1 and jpeg_free_idx != -1 and jpeg_zero_idx < jpeg_free_idx
    )
    return ok, "rgb_zero@%d<free@%d jpeg_zero@%d<free@%d" % (rgb_zero_idx, rgb_free_idx, jpeg_zero_idx, jpeg_free_idx)


# 33. no additional SSCMA/camera/network/NVS owner appeared (re-verify post-correction)
@check("33. no new SSCMA/camera/network/NVS owner introduced by the correction")
def _c33():
    text = _read(APP_C)
    hits = []
    for s in (
        "sscma_client_register_callback", "bsp_sscma_client_init",
        "sscma_client_sample", "sscma_client_invoke", "sscma_client_set_sensor",
        "esp_http_client", "storage_write", "storage_read", "nvs_",
    ):
        if s in text:
            hits.append(s)
    if any(s in text.lower() for s in ("ble_gap", "ble_gatt", "esp_ble", "nimble")):
        hits.append("ble-api")
    return not hits, "found: %s" % hits


def main():
    print("=== GPTNiX QR pairing foundation fitness test ===")
    print("FACTORY_DIR=%s" % FACTORY_DIR)
    if FAILURES:
        print("\n%d invariant(s) FAILED: %s" % (len(FAILURES), FAILURES))
        return 1
    print("\nAll invariants PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
