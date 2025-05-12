import json
import socket
import shlex
import sys
import getpass
import threading
import queue
import select
import time
from pathlib import Path
from crypto_utils import encrypt_file, decrypt_file, load_access_requests

CHUNK = 64 * 1024


def get_download_dir(username: str) -> Path:
    return Path(f"downloads-{username}")


class FileShareClient:
    def __init__(self):
        self.sock = None
        self.username = None
        self._password = None
        self._resp_q = queue.Queue()
        self._closed = threading.Event()
        self._busy = threading.Lock()

    def _readline_raw(self) -> str:
        buf = bytearray()
        self.sock.settimeout(5)
        while True:
            b = self.sock.recv(1)
            if not b:
                raise IOError("Socket closed")
            if b == b"\n":
                return buf.decode().strip()
            buf.extend(b)

    def _reader(self):
        buf = bytearray()
        while not self._closed.is_set():
            if not self._busy.acquire(False):
                time.sleep(0.02)
                continue
            try:
                r, _, _ = select.select([self.sock], [], [], 0.1)
                if r:
                    b = self.sock.recv(1)
                    if not b:
                        break
                    if b == b"\n":
                        line = buf.decode().strip()
                        buf.clear()
                        if line.startswith("NOTICE "):
                            print(f"\n[NOTIFY] {line[7:]}\np2p> ", end="")
                        else:
                            self._resp_q.put(line)
                    else:
                        buf.extend(b)
            finally:
                self._busy.release()
        self._closed.set()

    def _resp(self) -> str:
        if self._closed.is_set():
            raise IOError("connection closed")
        return self._resp_q.get()

    def connect(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self._closed.clear()
        threading.Thread(target=self._reader, daemon=True).start()
        print(f"[CLIENT] connected to {host}:{port}")

    def register(self):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        u = input("Username: ")
        p = getpass.getpass("Password: ")
        self.sock.sendall(f"REGISTER {u} {p}\n".encode())
        print("[CLIENT]", self._resp())

    def login(self):
        if not self.sock:
            return print("[CLIENT] connect first")
        u = input("Username: ")
        self.sock.sendall(f"LOGIN {u}\n".encode())
        if not self._resp().startswith("OK"):
            return
        p = getpass.getpass("Password: ")
        self.sock.sendall(f"PASS {p}\n".encode())
        resp = self._resp()
        print("[CLIENT]", resp)
        if resp.startswith("OK"):
            self.username = u
            self._password = p

    def list(self):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        self.sock.sendall(b"LIST\n")
        print("[CLIENT] files:", self._resp()[3:] or "(none)")

    def upload(self, path: Path):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        if not path.is_file():
            print("[CLIENT] not a file")
            return
        data = path.read_bytes()
        nonce, blob = encrypt_file(data)
        payload = nonce + blob
        with self._busy:
            self.sock.sendall(f"UPLOAD {path.name} {len(payload)}\n".encode())
            self.sock.sendall(payload)
            reply = self._readline_raw()
        print("[CLIENT]", reply)

    def download(self, name: str):
        if not self.sock:
            print("[CLIENT] connect first")
            return

        # Load grants and show what we’ve got
        acc = load_access_requests()
        grants = acc.get("grant", {})
        print(f"[DEBUG] all grants: {grants!r}")

        # Try to download the file using P2P
        retries = 3
        for attempt in range(retries):
            print(f"[DEBUG] Attempt {attempt + 1} of {retries} for P2P download.")
            if name in grants and self.username in grants[name]:
                info = grants[name][self.username]
                print(f"[DEBUG] attempting P2P download from {info['ip']}:{info['port']}")
                try:
                    with socket.create_connection((info["ip"], info["port"]), timeout=5) as s:
                        # re-authenticate on the peer
                        s.sendall(f"LOGIN {self.username}\n".encode())
                        _ = s.recv(64)  # consume OK password_required
                        s.sendall(f"PASS {self._password}\n".encode())
                        _ = s.recv(64)  # consume OK welcome

                        # request the file
                        s.sendall(f"DOWNLOAD {name}\n".encode())

                        # --- robust header read up to newline ---
                        header = bytearray()
                        while True:
                            b = s.recv(1)
                            if not b:
                                raise IOError("peer closed connection early")
                            header.extend(b)
                            if b == b"\n":
                                break
                        head = header.decode().strip()
                        print(f"[DEBUG] peer header: {head!r}")

                        if not head.startswith("OK "):
                            print(f"[CLIENT] peer error: {head}")
                            return

                        size = int(head.split()[1])
                        data = bytearray()
                        while len(data) < size:
                            chunk = s.recv(min(CHUNK, size - len(data)))
                            if not chunk:
                                raise IOError("incomplete file data")
                            data.extend(chunk)

                        return self._save_and_decrypt(name, data)

                except Exception as e:
                    print(f"[CLIENT] peer-to-peer download failed: {e}")
                    if attempt < retries - 1:
                        print("[DEBUG] Retrying...")
                    else:
                        print("[DEBUG] Falling back to central server...")
                        # fall through to central-server fallback
                        self._central_fallback(name)
                    break

    def _save_and_decrypt(self, name: str, data: bytes):
        """
        Saves the downloaded file after decrypting it.
        If decryption fails, saves the raw encrypted data.
        """
        nonce, ciphertext = data[:12], data[12:]
        try:
            plaintext = decrypt_file(nonce, ciphertext)  # Assuming decrypt_file is defined
            suffix = "(decrypted)"
        except Exception:
            plaintext = data  # If decryption fails, save the raw data
            suffix = "(plaintext)"

        # Define the download directory
        dest = get_download_dir(self.username) / name
        dest.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
        dest.write_bytes(plaintext)  # Save the file to disk

        print(f"[CLIENT] saved {name} {suffix}")

    def request(self, filename: str, host: str, port: int, owner: str):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        self.sock.sendall(f"REQUEST_REMOTE {filename} {host} {port} {owner}\n".encode())
        print("[CLIENT]", self._resp())

    def grant(self, filename: str, requester: str):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        self.sock.sendall(f"GRANT {filename} {requester}\n".encode())
        print("[CLIENT]", self._resp())

    def peerlist(self):
        if not self.sock:
            print("[CLIENT] connect first")
            return
        self.sock.sendall(b"PEERLIST\n")
        print("[CLIENT] peer files:", self._resp()[3:] or "(none)")

    HELP = (
        "commands:\n"
        "  connect <host> <port>\n"
        "  register | login\n"
        "  list | upload <file> | download <name>\n"
        "  request <file> <host> <port> <owner>\n"
        "  grant <file> <requester>\n"
        "  peerlist | quit"
    )

    def main_loop(self):
        while True:
            try:
                parts = shlex.split(input("p2p> "), posix=False)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not parts:
                continue
            cmd, *a = parts
            try:
                match cmd:
                    case "connect":   self.connect(a[0], int(a[1]))
                    case "register":  self.register()
                    case "login":     self.login()
                    case "list":      self.list()
                    case "upload":    self.upload(Path(a[0]))
                    case "download":  self.download(a[0])
                    case "request":   self.request(a[0], a[1], int(a[2]), a[3])
                    case "grant":     self.grant(a[0], a[1])
                    case "peerlist":  self.peerlist()
                    case "quit":      break
                    case _:           print(self.HELP)
            except Exception as e:
                print("[CLIENT ERROR]", e)
                print(self.HELP)
