import json, os, subprocess, mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI_DIR = os.path.join(BASE_DIR, "dashboard-ui")
ASM_DIR = os.path.join(BASE_DIR, "assembly-engine")
EXE_PATH = os.path.join(ASM_DIR, "crypto_engine.exe")

class BridgeHandler(BaseHTTPRequestHandler):
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
            body = json.dumps({"status": "ok", "engine": "assembly", "binary": os.path.exists(EXE_PATH)}).encode()
            self.send_response(200)
            self.send_cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        rel = "index.html" if self.path in ("/", "") else self.path.lstrip("/").split("?")[0]
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
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        text = payload.get("text", "")
        key  = payload.get("key", "")
        mode = payload.get("mode", "encrypt")

        # file_handler.asm reads key.txt as:
        #   line 1 — single mode char  'E' (encrypt) or 'D' (decrypt)
        #   line 2 — key string
        # It reads input.txt for the plaintext.
        # It takes NO command-line arguments.
        mode_char = "E" if str(mode).upper() in ("E", "ENCRYPT") else "D"

        with open(os.path.join(ASM_DIR, "key.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(mode_char + "\n")
            f.write(key + "\n")

        with open(os.path.join(ASM_DIR, "input.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

        proc = subprocess.run([EXE_PATH], cwd=ASM_DIR, capture_output=True)

        # output.txt contains raw processed bytes — read as binary, transport as latin-1
        out_path  = os.path.join(ASM_DIR, "output.txt")
        meta_path = os.path.join(ASM_DIR, "meta.txt")

        result_bytes = open(out_path, "rb").read() if os.path.exists(out_path) else b""
        result_str   = result_bytes.decode("latin-1")

        # meta.txt format written by file_handler.asm:
        #   === Processed Bytes (Hex) ===\r\n
        #   XX XX XX ...\r\n          (16 bytes per line)
        #   \r\n
        #   === Checksum (32-bit) ===\r\n
        #   XXXXXXXX\r\n
        hex_dump  = ""
        checksum  = ""
        if os.path.exists(meta_path):
            meta_text    = open(meta_path, "r", encoding="utf-8", errors="replace").read()
            lines        = meta_text.splitlines()
            in_hex       = False
            after_chk    = False
            hex_lines    = []
            for line in lines:
                if "Processed Bytes" in line and "===" in line:
                    in_hex = True
                    continue
                if "Checksum" in line and "===" in line:
                    in_hex    = False
                    after_chk = True
                    continue
                if in_hex and line.strip():
                    hex_lines.append(line.strip())
                if after_chk and line.strip():
                    checksum  = line.strip()
                    after_chk = False
            hex_dump = "\n".join(hex_lines)

        resp = json.dumps({
            "result":   result_str,
            "hexDump":  hex_dump,
            "checksum": checksum,
            "engine":   "assembly",
            "exitCode": proc.returncode,
        }).encode("utf-8")

        self.send_response(200)
        self.send_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

print(f"Server live at http://127.0.0.1:5000 | EXE: {os.path.exists(EXE_PATH)}")
HTTPServer(("0.0.0.0", 5000), BridgeHandler).serve_forever()
