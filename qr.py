import json
import uuid
import hashlib
import re
import time
import base64
from http.server import BaseHTTPRequestHandler
import requests as req_lib

# In-memory session store (Vercel serverless: use Redis/KV in production)
# For demo: sessions stored in module-level dict (single instance only)
_sessions = {}

ZALO_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

def _get_qr_post_headers(user_agent):
    return {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc",
        "User-Agent": user_agent,
    }

def _load_login_page(session, user_agent):
    url = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F"
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": "https://chat.zalo.me/",
        "User-Agent": user_agent,
    }
    r = session.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    match = re.search(r"https:\/\/stc-zlogin\.zdn\.vn\/main-([\d.]+)\.js", r.text)
    return match.group(1) if match else None

def _get_login_info(session, user_agent, version):
    url = "https://id.zalo.me/account/logininfo"
    data = {"continue": "https://zalo.me/pc", "v": version}
    r = session.post(url, headers=_get_qr_post_headers(user_agent), data=data, timeout=15)
    r.raise_for_status()
    return r.json()

def _verify_client(session, user_agent, version):
    url = "https://id.zalo.me/account/verify-client"
    data = {"type": "device", "continue": "https://zalo.me/pc", "v": version}
    r = session.post(url, headers=_get_qr_post_headers(user_agent), data=data, timeout=15)
    r.raise_for_status()
    return r.json()

def _qr_generate(session, user_agent, version):
    url = "https://id.zalo.me/account/authen/qr/generate"
    data = {"continue": "https://zalo.me/pc", "v": version}
    r = session.post(url, headers=_get_qr_post_headers(user_agent), data=data, timeout=15)
    r.raise_for_status()
    result = r.json()
    if result.get("error_code") != 0:
        raise Exception(f"QR generate failed: {result.get('error_message')}")
    return result.get("data", {})


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            session = req_lib.Session()
            session.headers.update({"User-Agent": ZALO_UA})

            # Step 1: load login page → version
            version = _load_login_page(session, ZALO_UA)
            if not version:
                self._json(500, {"error": "Không lấy được version từ Zalo."})
                return

            # Step 2: logininfo + verify-client
            _get_login_info(session, ZALO_UA, version)
            _verify_client(session, ZALO_UA, version)

            # Step 3: generate QR
            qr_data = _qr_generate(session, ZALO_UA, version)
            code = qr_data.get("code")
            image_b64 = qr_data.get("image", "").replace("data:image/png;base64,", "")

            if not code:
                self._json(500, {"error": "Zalo không trả về mã QR."})
                return

            # Store session for polling
            token = str(uuid.uuid4())
            _sessions[token] = {
                "session":  session,
                "version":  version,
                "code":     code,
                "status":   "waiting",
                "created":  time.time(),
                "imei":     None,
                "cookies":  None,
            }

            self._json(200, {
                "session_token": token,
                "qr_image": image_b64,
                "code": code,
            })

        except Exception as e:
            self._json(500, {"error": str(e)})

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a): pass
