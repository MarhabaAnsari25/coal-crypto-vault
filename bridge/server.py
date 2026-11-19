"""
bridge/server.py
Lightweight HTTP bridge for coal-crypto-vault.

Exposes POST /process on port 5000.
Request  JSON : { "text": str, "key": str, "mode": "E" | "D" }
Response JSON : { "result": str, "hexDump": str, "checksum": str }

When crypto_engine.exe is present in ../assembly-engine/ the request is
forwarded to it via subprocess.  If the binary does not exist the pure-Python
fallback replicates the EXACT same multi-byte rolling-XOR + ROL 3 algorithm
defined in assembly-engine/crypto_logic.inc, plus the ROL-1 checksum from
ComputeChecksum.

No third-party packages are required; only the Python standard library is used.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE_DIR  = os.path.normpath(os.path.join(_HERE, "..", "assembly-engine"))
_INPUT_FILE  = os.path.join(_ENGINE_DIR, "input.txt")
_KEY_FILE    = os.path.join(_ENGINE_DIR, "key.txt")
_OUTPUT_FILE = os.path.join(_ENGINE_DIR, "output.txt")
_META_FILE   = os.path.join(_ENGINE_DIR, "meta.txt")
_EXE_PATH    = os.path.join(_ENGINE_DIR, "crypto_engine.exe")

PORT = 5000

# ---------------------------------------------------------------------------
# Pure-Python crypto fallback
# Mirrors crypto_logic.inc exactly:
#
# EncryptBuffer per byte:
#   1. XOR with key[keyIndex % keyLen]
#   2. ROL AL, 3
#   3. keyIndex++
#
# DecryptBuffer per byte (exact inverse):
#   1. ROR AL, 3
#   2. XOR with key[keyIndex % keyLen]
#   3. keyIndex++
#
# ComputeChecksum:
#   checksum = 0
#   for each byte b: checksum = ROL32(checksum, 1) XOR b
# ---------------------------------------------------------------------------

def _rol8(value: int, shift: int) -> int:
    """Rotate an 8-bit value left by `shift` bits."""
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def _ror8(value: int, shift: int) -> int:
    """Rotate an 8-bit value right by `shift` bits."""
    shift &= 7
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def _rol32(value: int, shift: int) -> int:
    """Rotate a 32-bit value left by `shift` bits."""
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def _encrypt_buffer(data: bytes, key: bytes) -> bytes:
    """Encrypt using rolling-XOR then ROL-3 (matches EncryptBuffer in .inc)."""
    if not key:
        return data
    key_len = len(key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        b = byte ^ key[i % key_len]   # rolling XOR
        b = _rol8(b, 3)                # ROL AL, 3
        out[i] = b
    return bytes(out)


def _decrypt_buffer(data: bytes, key: bytes) -> bytes:
    """Decrypt using ROR-3 then rolling-XOR (matches DecryptBuffer in .inc)."""
    if not key:
        return data
    key_len = len(key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        b = _ror8(byte, 3)             # ROR AL, 3  (undo rotation first)
        b ^= key[i % key_len]          # XOR (undo rolling XOR)
        out[i] = b
    return bytes(out)


def _compute_checksum(data: bytes) -> int:
    """32-bit rolling checksum: checksum = ROL32(checksum, 1) XOR byte."""
    checksum = 0
    for byte in data:
        checksum = _rol32(checksum, 1) ^ byte
    return checksum


def _build_hex_dump(data: bytes) -> str:
    """
    Build a hex-dump string identical to what file_handler.asm writes to
    meta.txt: uppercase pairs separated by spaces, 16 bytes per line.
    """
    if not data:
        return ""
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        lines.append(" ".join(f"{b:02X}" for b in chunk))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Processing logic
# ---------------------------------------------------------------------------

def _process_with_exe(text: str, key: str, mode: str) -> dict:
    """
    Delegate to crypto_engine.exe.  Writes input/key files, runs the binary,
    reads output.txt and meta.txt, and parses the response.
    """
    # Write input text
    with open(_INPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(text)

    # Write key file: line 1 = mode, line 2 = key
    with open(_KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(f"{mode.upper()}\n{key}\n")

    # Run the engine
    subprocess.run(
        [_EXE_PATH],
        cwd=_ENGINE_DIR,
        check=True,
        capture_output=True,
    )

    # Read output.txt (processed bytes – raw binary so multi-byte data survives)
    with open(_OUTPUT_FILE, "rb") as fh:
        result_bytes = fh.read()

    # Read meta.txt and extract checksum line
    with open(_META_FILE, "r", encoding="utf-8", errors="replace") as fh:
        meta_text = fh.read()

    # Build response
    result_str = result_bytes.decode("latin-1")  # lossless round-trip for binary
    hex_dump   = _build_hex_dump(result_bytes)
    checksum   = _parse_checksum_from_meta(meta_text)

    return {"result": result_str, "hexDump": hex_dump, "checksum": checksum}


def _parse_checksum_from_meta(meta_text: str) -> str:
    """
    Extract the 8-char hex checksum line that follows the
    '=== Checksum (32-bit) ===' header written by file_handler.asm.
    Falls back to the last non-empty line if the header is absent.
    """
    lines = meta_text.splitlines()
    capture_next = False
    for line in lines:
        if capture_next:
            stripped = line.strip()
            if stripped:
                return stripped
        if "Checksum" in line and "===" in line:
            capture_next = True
    # Fallback: last non-empty line
    for line in reversed(lines):
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _process_with_fallback(text: str, key: str, mode: str) -> dict:
    """
    Pure-Python simulation.  Exactly mirrors the assembly algorithms so
    results are byte-for-byte identical to what the .exe would produce.
    """
    data     = text.encode("utf-8")
    key_data = key.encode("utf-8")
    m        = mode.upper()

    if m == "E":
        result_bytes = _encrypt_buffer(data, key_data)
    elif m == "D":
        result_bytes = _decrypt_buffer(data, key_data)
    else:
        result_bytes = data  # unknown mode: pass-through (matches ASM behaviour)

    checksum_int = _compute_checksum(result_bytes)
    checksum_str = f"{checksum_int:08X}"
    hex_dump     = _build_hex_dump(result_bytes)

    # Decode result for JSON transport; use latin-1 so every byte survives
    result_str = result_bytes.decode("latin-1")

    return {
        "result":   result_str,
        "hexDump":  hex_dump,
        "checksum": checksum_str,
    }


def process_request(text: str, key: str, mode: str) -> dict:
    """Route to EXE or Python fallback depending on whether the binary exists."""
    if os.path.isfile(_EXE_PATH):
        return _process_with_exe(text, key, mode)
    return _process_with_fallback(text, key, mode)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class CryptoHandler(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler with CORS support."""

    # Silence the default access-log noise; keep it for errors only.
    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        if args and str(args[1]) not in ("200", "204"):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------------
    # CORS helpers
    # ------------------------------------------------------------------
    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization"
        )

    # ------------------------------------------------------------------
    # Pre-flight
    # ------------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    # ------------------------------------------------------------------
    # POST /process
    # ------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/process":
            self._send_json({"error": "Not found"}, status=404)
            return

        # Read body
        length = int(self.headers.get("Content-Length", 0))
        raw    = self.rfile.read(length)

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._send_json({"error": f"Invalid JSON: {exc}"}, status=400)
            return

        # Validate required fields
        text = payload.get("text")
        key  = payload.get("key")
        mode = payload.get("mode", "")

        if text is None or key is None:
            self._send_json(
                {"error": "Missing required fields: text, key"}, status=400
            )
            return

        if str(mode).upper() not in ("E", "D"):
            self._send_json(
                {"error": "mode must be 'E' (encrypt) or 'D' (decrypt)"}, status=400
            )
            return

        try:
            response = process_request(str(text), str(key), str(mode))
        except subprocess.CalledProcessError as exc:
            self._send_json(
                {"error": f"crypto_engine.exe failed (exit {exc.returncode})"},
                status=500,
            )
            return
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json(response, status=200)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------
    def _send_json(self, data: dict, *, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    engine_note = (
        f"  crypto_engine.exe found  → using binary at {_EXE_PATH}"
        if os.path.isfile(_EXE_PATH)
        else "  crypto_engine.exe NOT found → using pure-Python fallback"
    )
    print(f"coal-crypto-vault bridge server")
    print(f"  Listening on http://0.0.0.0:{PORT}")
    print(f"  Endpoint : POST /process")
    print(engine_note)
    print("  Press Ctrl+C to stop.\n")

    server = HTTPServer(("0.0.0.0", PORT), CryptoHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
