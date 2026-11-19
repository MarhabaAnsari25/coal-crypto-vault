import json, os, subprocess, mimetypes, base64, re
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR   = os.path.join(BASE_DIR, "dashboard-ui")
ASM_DIR  = os.path.join(BASE_DIR, "assembly-engine")
EXE_PATH = os.path.join(ASM_DIR, "crypto_engine.exe")

# ─────────────────────────────────────────────────────────────
# Pure-Python cipher  (exact mirror of crypto_logic.inc)
#
# Encrypt byte b at index i with key k:
#   1. xored  = b ^ k[i % len(k)]   (rolling XOR)
#   2. result = ROL3(xored)          (rotate-left 3 bits)
#
# Decrypt byte b at index i with key k:
#   1. rored  = ROR3(b)              (rotate-right 3 bits)
#   2. result = rored ^ k[i % len(k)]
# ─────────────────────────────────────────────────────────────

def _rol3(b: int) -> int:
    return ((b << 3) | (b >> 5)) & 0xFF

def _ror3(b: int) -> int:
    return ((b >> 3) | (b << 5)) & 0xFF

def _xor_checksum32(data: bytes) -> int:
    csum = 0
    for i, byte in enumerate(data):
        csum ^= (byte << ((i % 4) * 8))
    return csum & 0xFFFFFFFF

def py_encrypt(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(_rol3(b ^ key[i % klen]) for i, b in enumerate(data))

def py_decrypt(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(_ror3(b) ^ key[i % klen] for i, b in enumerate(data))


# ─────────────────────────────────────────────────────────────
# Try the assembly EXE first; fall back to Python if it fails.
# ─────────────────────────────────────────────────────────────

def run_asm_engine(raw_in: bytes, key: str, mode: str):
    """
    Write files, invoke EXE, read output.txt.
    Returns (output_bytes, engine_label) or raises RuntimeError.
    """
    mode_char = "E" if mode == "encrypt" else "D"
    with open(os.path.join(ASM_DIR, "key.txt"), "w", encoding="utf-8", newline="\r\n") as f:
        f.write(f"{mode_char}\n{key}\n")

    with open(os.path.join(ASM_DIR, "input.txt"), "wb") as f:
        f.write(raw_in)

    out_path = os.path.join(ASM_DIR, "output.txt")
    if os.path.exists(out_path):
        os.remove(out_path)

    result = subprocess.run([EXE_PATH], cwd=ASM_DIR, check=False, timeout=5)

    if result.returncode != 0:
        raise RuntimeError(f"EXE exited with code {result.returncode}")

    if not os.path.exists(out_path):
        raise RuntimeError("EXE produced no output.txt")

    raw_out = open(out_path, "rb").read()
    if len(raw_out) == 0 and len(raw_in) > 0:
        raise RuntimeError("EXE wrote 0 bytes")

    return raw_out, "IA-32 Assembly"


def process_crypto(text: str, key: str, mode: str):
    """
    Main processing entry point.
    Returns dict with result, checksum, bytes, engine.
    """
    key_bytes = key.encode("utf-8")
    if not key_bytes:
        raise ValueError("Key must not be empty")

    # Prepare raw input bytes
    if mode == "encrypt":
        raw_in = text.encode("utf-8")
    else:
        try:
            raw_in = base64.b64decode(text.strip())
        except Exception:
            raw_in = text.encode("utf-8")

    raw_out   = None
    engine    = ""

    # 1. Try ASM engine
    if os.path.exists(EXE_PATH):
        try:
            raw_out, engine = run_asm_engine(raw_in, key, mode)
        except Exception as e:
            print(f"[ASM engine failed: {e}] — falling back to Python engine")

    # 2. Python fallback
    if raw_out is None:
        if mode == "encrypt":
            raw_out = py_encrypt(raw_in, key_bytes)
        else:
            raw_out = py_decrypt(raw_in, key_bytes)
        engine = "Python (Rolling-XOR+ROL3)"

    # Build result string
    if mode == "encrypt":
        result = base64.b64encode(raw_out).decode("ascii")
    else:
        result = raw_out.decode("utf-8", errors="replace")

    # Checksum from meta.txt (ASM) or compute ourselves
    checksum = ""
    meta_path = os.path.join(ASM_DIR, "meta.txt")
    if os.path.exists(meta_path) and "Assembly" in engine:
        meta_txt = open(meta_path, "r", encoding="utf-8", errors="replace").read()
        m = re.search(r"([0-9A-Fa-f]{8})", meta_txt.split("Checksum")[-1])
        if m:
            checksum = "0x" + m.group(1).upper()

    if not checksum:
        csum = _xor_checksum32(raw_out)
        checksum = "0x" + format(csum, "08X")

    return {
        "result":   result,
        "output":   result,
        "checksum": checksum,
        "bytes":    len(raw_out),
        "engine":   engine,
    }


# ─────────────────────────────────────────────────────────────
# HTTP Server
# ─────────────────────────────────────────────────────────────

class BridgeHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Keep console clean — only print errors
        pass

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.end_headers()

    def do_GET(self):
        if self.path == "/ping":
            body = json.dumps({
                "status": "ok",
                "engine": "Python (Rolling-XOR+ROL3)",
                "binary": os.path.exists(EXE_PATH),
            }).encode()
            self.send_response(200)
            self.send_cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        rel       = "index.html" if self.path in ("/", "") else self.path.lstrip("/").split("?")[0]
        file_path = os.path.join(UI_DIR, rel)
        if os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                data = f.read()
            ctype = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
            self.send_response(200)
            self.send_cors()
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.send_cors()
            self.end_headers()

    def do_POST(self):
        if self.path != "/process":
            self.send_response(404)
            self.send_cors()
            self.end_headers()
            return

        length  = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))

        text = payload.get("text", "")
        key  = payload.get("key", "")
        mode = payload.get("mode", "encrypt").lower()

        try:
            resp_data = process_crypto(text, key, mode)
            status    = 200
        except Exception as e:
            resp_data = {"error": str(e)}
            status    = 500

        body = json.dumps(resp_data).encode("utf-8")
        self.send_response(status)
        self.send_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


print("=" * 55)
print("  Coal Crypto Vault — Bridge Server")
print(f"  http://127.0.0.1:5000")
print(f"  ASM EXE present : {os.path.exists(EXE_PATH)}")
print(f"  Fallback engine : Python (Rolling-XOR + ROL3)")
print("=" * 55)

HTTPServer(("0.0.0.0", 5000), BridgeHandler).serve_forever()
