from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import time
import hmac
import hashlib
import secrets
import threading

# ================= 系統核心安全設定（優先讀取 Render 環境變數） =================
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8080"))
API_SECRET = os.environ.get("API_SECRET", "CHANGE_ME_API_SECRET")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN")
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys_db.json")
# ==============================================================================

db_lock = threading.Lock()


def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_db(data):
    tmp_file = DB_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, DB_FILE)


def make_signature(payload_str: str) -> str:
    return hmac.new(
        API_SECRET.encode("utf-8"),
        payload_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def format_expire_time(ts: float) -> str:
    if ts == 0:
        return "永久有效"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class LicenseHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}")

    def _send_json(self, code: int, obj: dict):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > 65536:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _check_admin(self) -> bool:
        auth = self.headers.get("X-Admin-Token", "")
        return hmac.compare_digest(auth, ADMIN_TOKEN)

    def do_POST(self):
        data = self._read_json()

        # ---------------- 買家端驗證 API ----------------
        if self.path == "/api/verify":
            key = str(data.get("key", "")).strip().upper()
            hwid = str(data.get("hwid", "")).strip()
            nonce = str(data.get("nonce", "")).strip()
            client_ts = int(data.get("ts", 0))

            if not key or not hwid or not nonce:
                return self._send_json(400, {"ok": False, "msg": "請求參數不完整"})

            now = int(time.time())
            if abs(now - client_ts) > 300:
                return self._send_json(400, {"ok": False, "msg": "本機系統時間誤差過大，請先校準電腦時間"})

            with db_lock:
                db = load_db()
                info = db.get(key)
                if not info:
                    return self._send_json(200, {"ok": False, "msg": "無效的卡密，請確認是否輸入錯誤"})

                if info.get("banned", False):
                    return self._send_json(200, {"ok": False, "msg": "此卡密已被管理員停用封鎖"})

                days = float(info.get("days", 1))
                # 首次啟用時開始計算到期時間並綁定 HWID
                if not info.get("activated_at"):
                    info["activated_at"] = now
                    info["expires_at"] = 0 if days <= 0 else int(now + days * 86400)
                    info["hwid"] = hwid
                    db[key] = info
                    save_db(db)
                else:
                    saved_hwid = info.get("hwid", "")
                    if saved_hwid and saved_hwid != hwid:
                        return self._send_json(200, {"ok": False, "msg": "此卡密已綁定其他電腦，如需換機請聯繫客服"})
                    if not saved_hwid:
                        info["hwid"] = hwid
                        db[key] = info
                        save_db(db)

                expires_at = int(info.get("expires_at", 0))
                if expires_at != 0 and now > expires_at:
                    return self._send_json(200, {"ok": False, "msg": f"卡密已於 {format_expire_time(expires_at)} 到期"})

                exp_text = format_expire_time(expires_at)
                # 產生防偽造動態簽章
                sign_raw = f"OK|{key}|{hwid}|{nonce}|{expires_at}|{now}"
                sig = make_signature(sign_raw)

                return self._send_json(200, {
                    "ok": True,
                    "msg": "驗證成功",
                    "expires_at": expires_at,
                    "expires_text": exp_text,
                    "server_ts": now,
                    "sig": sig
                })

        # ---------------- 管理員後台 API ----------------
        if not self._check_admin():
            return self._send_json(401, {"ok": False, "msg": "管理員密碼錯誤"})

        if self.path == "/admin/generate":
            count = max(1, min(100, int(data.get("count", 1))))
            days = float(data.get("days", 1))
            prefix = str(data.get("prefix", "YI")).strip().upper() or "YI"
            note = str(data.get("note", "")).strip()

            tag = "PERM" if days <= 0 else (f"{int(days)}D" if days.is_integer() else f"{days}D")
            created = []

            with db_lock:
                db = load_db()
                for _ in range(count):
                    while True:
                        part1 = secrets.token_hex(2).upper()
                        part2 = secrets.token_hex(2).upper()
                        part3 = secrets.token_hex(2).upper()
                        new_key = f"{prefix}-{tag}-{part1}-{part2}-{part3}"
                        if new_key not in db:
                            break
                    db[new_key] = {
                        "days": days,
                        "created_at": int(time.time()),
                        "activated_at": None,
                        "expires_at": None,
                        "hwid": "",
                        "banned": False,
                        "note": note
                    }
                    created.append(new_key)
                save_db(db)

            return self._send_json(200, {"ok": True, "keys": created})

        elif self.path == "/admin/list":
            with db_lock:
                db = load_db()
            return self._send_json(200, {"ok": True, "db": db})

        elif self.path == "/admin/action":
            key = str(data.get("key", "")).strip().upper()
            action = str(data.get("action", "")).strip()

            with db_lock:
                db = load_db()
                if key not in db:
                    return self._send_json(404, {"ok": False, "msg": "找不到該卡密"})

                if action == "reset_hwid":
                    db[key]["hwid"] = ""
                    msg = "已解除電腦機器碼綁定"
                elif action == "ban":
                    db[key]["banned"] = True
                    msg = "已封鎖此卡密"
                elif action == "unban":
                    db[key]["banned"] = False
                    msg = "已解除封鎖"
                elif action == "delete":
                    del db[key]
                    msg = "已永久刪除該卡密"
                else:
                    return self._send_json(400, {"ok": False, "msg": "未知的操作指令"})

                save_db(db)
            return self._send_json(200, {"ok": True, "msg": msg})

        return self._send_json(404, {"ok": False, "msg": "未知路徑"})


if __name__ == "__main__":
    print(f"[*] Roblox YI 商業卡密驗證伺服器已啟動 -> http://{HOST}:{PORT}")
    HTTPServer((HOST, PORT), LicenseHandler).serve_forever()