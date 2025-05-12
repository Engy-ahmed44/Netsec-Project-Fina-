import socket
import threading
import json
from pathlib import Path

from crypto_utils import (
    hash_password,
    verify_password,
    load_access_requests,
    save_access_requests,
)

def get_shared_dir(user: str) -> Path:
    return Path(f"shared-{user}")

class FileSharePeer:
    CHUNK     = 64 * 1024
    HOST      = "0.0.0.0"
    PEER_TOUT = 20
    USER_FILE = Path("users.json")

    def __init__(self, port: int):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.users = self._load_users()
        self.shared = {}
        self.sessions = {}
        self.pending_login = {}

        acc = load_access_requests()
        for fname, info in acc.get("private", {}).items():
            self.shared[fname] = {"path": info["path"], "owner": info["owner"]}

    def _load_users(self):
        if self.USER_FILE.exists():
            return json.loads(self.USER_FILE.read_text())
        return {}

    def _save_users(self):
        self.USER_FILE.write_text(json.dumps(self.users, indent=2))

    def _check_login(self, conn):
        return conn in self.sessions and self.sessions[conn] is not None

    def _readline(self, sock):
        buf = bytearray()
        while True:
            try:
                b = sock.recv(1)
                if not b or b == b'\n':
                    return buf.decode().strip()
                buf.extend(b)
            except (ConnectionAbortedError, ConnectionResetError):
                return None

    def _send_notice_to_user(self, user, text):
        for conn, u in list(self.sessions.items()):
            if u == user:
                try:
                    conn.sendall(f"NOTICE {text}\n".encode())
                except:
                    continue

    def start_peer(self):
        self.sock.bind((self.HOST, self.port))
        self.sock.listen(5)
        print(f"[PEER] listening on {self.HOST}:{self.port}")
        while True:
            conn, addr = self.sock.accept()
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        self.sessions[conn] = None
        try:
            while True:
                line = self._readline(conn)
                if line is None or line == "":
                    break
                parts = line.split()
                cmd = parts[0].upper()
                if cmd == "REGISTER":
                    self._register(conn, parts)
                elif cmd == "LOGIN":
                    self._login_user(conn, parts)
                elif cmd == "PASS":
                    self._login_pass(conn, parts)
                elif cmd == "LOGOUT":
                    self._logout_user(conn)
                elif cmd == "LIST":
                    self._list(conn)
                elif cmd == "UPLOAD":
                    self._upload(conn, parts)
                elif cmd == "DOWNLOAD":
                    self._download(conn, parts)
                elif cmd == "REQUEST_REMOTE":
                    self._remote_request(conn, parts)
                elif cmd == "GRANT":
                    self._grant_access(conn, parts)
                elif cmd == "PROXY_REQUEST":
                    self._proxy_request(conn, parts)
                elif cmd == "PROXY_NOTICE":
                    self._proxy_notice(parts)
                elif cmd == "PEERLIST":
                    self._peerlist(conn)
                else:
                    conn.sendall(b"ERR unknown_command\n")
        finally:
            self.sessions.pop(conn, None)
            self.pending_login.pop(conn, None)

    def _register(self, conn, p):
        if len(p) != 3:
            conn.sendall(b"ERR format\n"); return
        user, pw = p[1], p[2]
        if user in self.users:
            conn.sendall(b"ERR exists\n"); return
        rec = hash_password(pw)
        self.users[user] = [rec["hash"], rec["salt"]]
        self._save_users()
        conn.sendall(b"OK registered\n")

    def _login_user(self, conn, p):
        if len(p) != 2:
            conn.sendall(b"ERR format\n"); return
        user = p[1]
        if user not in self.users:
            conn.sendall(b"ERR no_user\n"); return
        self.pending_login[conn] = user
        conn.sendall(b"OK password_required\n")

    def _login_pass(self, conn, p):
        if len(p) != 2:
            conn.sendall(b"ERR format\n"); return
        user = self.pending_login.get(conn)
        if not user:
            conn.sendall(b"ERR login_step\n"); return
        stored = {"hash": self.users[user][0], "salt": self.users[user][1]}
        if verify_password(stored, p[1]):
            self.sessions[conn] = user
            del self.pending_login[conn]
            conn.sendall(b"OK welcome\n")
        else:
            conn.sendall(b"ERR bad_pwd\n")

    def _logout_user(self, conn):
        if not self._check_login(conn):
            conn.sendall(b"ERR not_logged_in\n"); return
        self.sessions[conn] = None
        conn.sendall(b"OK logged_out\n")

    def _list(self, conn):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return
        user = self.sessions[conn]
        acc = load_access_requests()
        visible = [f for f, meta in self.shared.items() if meta["owner"] == user]
        visible += [f for f, gr in acc.get("grant", {}).items() if user in gr]
        conn.sendall(f"OK {' '.join(visible)}\n".encode())

    def _upload(self, conn, p):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return
        if len(p) != 3:
            conn.sendall(b"ERR format\n"); return
        fname, size = p[1], int(p[2])
        user = self.sessions[conn]
        dest = get_shared_dir(user)
        dest.mkdir(parents=True, exist_ok=True)
        path = dest / fname
        with open(path, "wb") as f:
            rem = size
            while rem:
                chunk = conn.recv(min(self.CHUNK, rem))
                if not chunk: break
                f.write(chunk); rem -= len(chunk)
        self.shared[fname] = {"path": str(path), "owner": user}
        acc = load_access_requests()
        acc.setdefault("private", {})[fname] = {"owner": user, "path": str(path)}
        save_access_requests(acc)
        conn.sendall(b"OK stored\n")

    def _remote_request(self, conn, p):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return
        if len(p) != 5:
            conn.sendall(b"ERR format\n"); return
        fname, host, port_s, owner = p[1:]
        port = int(port_s)
        user = self.sessions[conn]
        acc = load_access_requests()
        acc.setdefault("request", {}).setdefault(fname, {})[user] = {
            "ip": conn.getpeername()[0],
            "port": self.port
        }
        save_access_requests(acc)
        notice = f"user '{user}' requested '{fname}' from you ({conn.getpeername()[0]}:{self.port})"
        if owner in self.sessions.values():
            self._send_notice_to_user(owner, notice)
            print(f"[NOTIFY] {notice}")
        try:
            with socket.create_connection((host, port), timeout=self.PEER_TOUT) as s:
                s.sendall(f"PROXY_REQUEST {fname} {user} {self.port}\n".encode())
        except:
            pass
        conn.sendall(b"OK requested\n")

    def _grant_access(self, conn, p):
        user = self.sessions.get(conn)
        if not user:
            conn.sendall(b"ERR login_required\n");
            return
        if len(p) != 3:
            conn.sendall(b"ERR format\n");
            return

        fname, req = p[1], p[2]
        acc = load_access_requests()
        reqs = acc.get("request", {}).get(fname, {})
        if req not in reqs:
            conn.sendall(b"ERR no_request\n");
            return

        # drop the old requester→their-address entry
        reqs.pop(req)

        # now record the *owner’s* real advertised endpoint
        owner_ip = "127.0.0.1"  # or self.advertised_ip if you set that above
        owner_port = self.port

        acc.setdefault("grant", {}).setdefault(fname, {})[req] = {
            "ip": owner_ip,
            "port": owner_port
        }
        # clean up empty request lists...
        if not acc["request"].get(fname):
            acc["request"].pop(fname)
        save_access_requests(acc)

        # notify requester if they’re online
        info = acc["grant"][fname][req]
        try:
            with socket.create_connection((info["ip"], info["port"]), timeout=self.PEER_TOUT) as s:
                s.sendall(f"PROXY_NOTICE {req} your request for '{fname}' has been granted\n".encode())
        except:
            pass

        conn.sendall(b"OK granted\n")

    def _download(self, conn, p):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return
        if len(p) != 2:
            conn.sendall(b"ERR format\n"); return
        fname = p[1]

        # 1) Serve private files
        meta = self.shared.get(fname)
        acc = load_access_requests()
        if meta:
            try:
                data = Path(meta["path"]).read_bytes()
                conn.sendall(f"OK {len(data)}\n".encode())
                conn.sendall(data)
            except Exception as e:
                conn.sendall(f"ERR file_read_failed {e}\n".encode())
            return

        # 2) Forward to owner if granted
        grants = acc.get("grant", {})
        owner = self.sessions[conn]
        if fname in grants and owner in grants[fname]:
            rec = grants[fname][owner]
            try:
                with socket.create_connection((rec["ip"], rec["port"]), timeout=self.PEER_TOUT) as s:
                    s.sendall(f"DOWNLOAD {fname}\n".encode())
                    hdr = s.recv(64).decode().strip().split()
                    if hdr[0] != "OK":
                        conn.sendall(f"ERR upstream_{hdr[0]}\n".encode())
                        return
                    size = int(hdr[1])
                    buf = bytearray()
                    while len(buf) < size:
                        buf.extend(s.recv(min(self.CHUNK, size - len(buf))))
                    conn.sendall(f"OK {len(buf)}\n".encode())
                    conn.sendall(buf)
            except Exception as e:
                conn.sendall(f"ERR remote_fail {e}\n".encode())
            return

        conn.sendall(b"ERR no_file\n")

    def _proxy_request(self, conn, p):
        if len(p) != 4:
            return
        fname, req_user, prt_s = p[1:]
        prt = int(prt_s)
        ip = conn.getpeername()[0]
        acc = load_access_requests()
        acc.setdefault("request", {}).setdefault(fname, {})[req_user] = {"ip": ip, "port": prt}
        save_access_requests(acc)
        owner = self.shared.get(fname, {}).get("owner")
        if owner in self.sessions.values():
            notice = f"user '{req_user}' requested '{fname}' from you ({ip}:{prt})"
            self._send_notice_to_user(owner, notice)
            print(f"[NOTIFY] {notice}")

    def _proxy_notice(self, p):
        if len(p) < 3:
            return
        tgt, msg = p[1], " ".join(p[2:])
        for conn, u in self.sessions.items():
            if u == tgt:
                try:
                    conn.sendall(f"NOTICE {msg}\n".encode())
                except:
                    continue

    def _peerlist(self, conn):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return

        acc = load_access_requests()
        grant_m = acc.get("grant", {})
        req_m   = acc.get("request", {})
        priv    = acc.get("private", {})

        entries = []

        for fname, meta in grant_m.items():
            heads = ",".join(meta.keys())
            owner = priv.get(fname, {}).get("owner", "unknown")
            entries.append(f"{fname} [status:granted:(<{heads}>) | owner:{owner}]")

        for fname, meta in req_m.items():
            heads = ",".join(meta.keys())
            owner = priv.get(fname, {}).get("owner", "unknown")
            entries.append(f"{fname} [status:requested:(<{heads}>) | owner:{owner}]")

        for fname, info in priv.items():
            owner = info.get("owner", "unknown")
            entries.append(f"{fname} [status:private | owner:{owner}]")

        conn.sendall(f"OK {','.join(entries)}\n".encode())

    def _list_requests(self, conn):
        if not self._check_login(conn):
            conn.sendall(b"ERR login_required\n"); return
        acc = load_access_requests()
        lines = []
        for fn, reqs in acc.get("request", {}).items():
            for r in reqs:
                lines.append(f"{r} -> {fn}")
        conn.sendall(f"OK {';'.join(lines)}\n".encode())

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    peer = FileSharePeer(port)
    peer.start_peer()