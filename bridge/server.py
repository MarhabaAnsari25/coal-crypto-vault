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
        key = payload.get("key", "")
        mode = payload.get("mode", "encrypt")

        with open(os.path.join(ASM_DIR, "input.txt"), "w", encoding="utf-8") as f:
            f.write(text)
        with open(os.path.join(ASM_DIR, "key.txt"), "w", encoding="utf-8") as f:
            f.write(key)
        with open(os.path.join(ASM_DIR, "mode.txt"), "w", encoding="utf-8") as f:
            f.write("E" if mode == "encrypt" else "D")

        subprocess.run([EXE_PATH], cwd=ASM_DIR, check=False)

        out_path = os.path.join(ASM_DIR, "output.txt")
        result = open(out_path, "r", encoding="utf-8", errors="replace").read() if os.path.exists(out_path) else ""
        resp = json.dumps({"result": result, "engine": "assembly"}).encode("utf-8")
        self.send_response(200)
        self.send_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

print(f"Server live at http://127.0.0.1:5000 | EXE: {os.path.exists(EXE_PATH)}")
HTTPServer(("0.0.0.0", 5000), BridgeHandler).serve_forever()
