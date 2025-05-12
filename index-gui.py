import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QStackedWidget,
    QListWidget, QTextEdit, QFileDialog, QMessageBox,
    QInputDialog, QDialog, QVBoxLayout, QLabel
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap

# Import your modules
from crypto_utils import encrypt_file
from fileshare_client import FileShareClient
from fileshare_peer import FileSharePeer
from PyQt6.QtCore import QTimer



# =============================
# Dialogs
# =============================

class GrantRequestDialog(QDialog):
    def __init__(self, requester, filename, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Access Request")
        self.requester = requester
        self.filename = filename
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"User '{self.requester}' wants access to:\n{self.filename}"))
        grant_btn = QPushButton("Grant Access")
        deny_btn = QPushButton("Deny")

        grant_btn.clicked.connect(self.accept)
        deny_btn.clicked.connect(self.reject)

        layout.addWidget(grant_btn)
        layout.addWidget(deny_btn)
        self.setLayout(layout)


# =============================
# Pages
# =============================

class ConnectPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()
        

    def initUI(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        host_layout = QHBoxLayout()
        self.host_input = QLineEdit("localhost")
        self.port_input = QLineEdit("8888")

        host_layout.addWidget(QLabel("Host:"))
        host_layout.addWidget(self.host_input)
        host_layout.addWidget(QLabel("Port:"))
        host_layout.addWidget(self.port_input)

        self.connect_btn = QPushButton("Connect")
        layout.addLayout(host_layout)
        layout.addWidget(self.connect_btn)

        self.setLayout(layout)


class GuestPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")

        layout.addWidget(QLabel("You are not logged in.", alignment=Qt.AlignmentFlag.AlignCenter))
        layout.addWidget(self.login_btn)
        layout.addWidget(self.register_btn)

        self.setLayout(layout)


class HomePage(QWidget):
    def __init__(self, controller=None, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.username = None
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Top Status Label
        self.status_label = QLabel()
        self.status_label.setStyleSheet("font-weight: bold; padding: 5px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)

        # Button Row for Logout & Disconnect
        btn_layout = QHBoxLayout()
        self.logout_btn = QPushButton("Logout")
        self.disconnect_btn = QPushButton("Disconnect")
        self.logout_btn.clicked.connect(lambda: self.controller.handle_logout(logout_only=True))
        self.disconnect_btn.clicked.connect(lambda: self.controller.handle_logout(logout_only=False))
        btn_layout.addWidget(self.logout_btn)
        btn_layout.addWidget(self.disconnect_btn)
        layout.addLayout(btn_layout)


        # My Files Section
        my_files_layout = QHBoxLayout()
        self.my_files = QListWidget()
        self.refresh_my_btn = QPushButton("Refresh My Files")
        self.refresh_my_btn.clicked.connect(lambda: self.controller.refresh_my_files())
        my_files_layout.addWidget(QLabel("My Files:"))
        my_files_layout.addWidget(self.refresh_my_btn)
        layout.addLayout(my_files_layout)
        layout.addWidget(self.my_files)

        # Peer Files Section
        peer_files_layout = QHBoxLayout()
        self.peer_files = QListWidget()
        self.refresh_peer_btn = QPushButton("Refresh Peer Files")
        self.refresh_peer_btn.clicked.connect(lambda: self.controller.refresh_peer_files())
        peer_files_layout.addWidget(QLabel("Peer Files:"))
        peer_files_layout.addWidget(self.refresh_peer_btn)
        layout.addLayout(peer_files_layout)
        layout.addWidget(self.peer_files)

        # === NEW SECTION: Pending Requests ===
        request_files_layout = QHBoxLayout()
        self.request_list = QListWidget()
        self.refresh_req_btn = QPushButton("Refresh Files Requests")
        self.refresh_req_btn.clicked.connect(lambda: self.controller.refresh_request_list())
        self.grant_btn = QPushButton("Grant Selected Request")
        self.grant_btn.clicked.connect(self.handle_grant)
        request_files_layout.addWidget(QLabel("Pending Requests:"))
        peer_files_layout.addWidget(self.refresh_req_btn)
        layout.addWidget(self.request_list)
        layout.addWidget(self.grant_btn)

        # Buttons
        btn_layout = QHBoxLayout()
        self.request_btn = QPushButton("Request Selected File")
        self.download_btn = QPushButton("Download Selected File")
        self.request_btn.clicked.connect(self.request_file)
        self.download_btn.clicked.connect(self.download_file)
        btn_layout.addWidget(self.request_btn)
        btn_layout.addWidget(self.download_btn)
        layout.addLayout(btn_layout)

        # Image Preview
        self.image_preview = QLabel("Image Preview")
        self.image_preview.setFixedSize(400, 300)
        self.image_preview.setStyleSheet("border: 1px solid #ccc;")
        self.image_preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.image_preview)

        # Drag & Drop Area
        self.drop_label = QLabel("Drag & Drop Images Here")
        self.drop_label.setAcceptDrops(True)
        self.drop_label.setStyleSheet("border: 2px dashed #aaa; padding: 20px;")
        self.drop_label.setMinimumHeight(100)
        self.drop_label.dragEnterEvent = self.dragEnterEvent
        self.drop_label.dropEvent = self.dropImageFile
        layout.addWidget(self.drop_label)

        # Console Output
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(QLabel("Console:"))
        layout.addWidget(self.console)

        self.setLayout(layout)
        self.refresh_my_btn.click()

    def handle_grant(self):
        selected = self.request_list.currentItem()
        if not selected:
            return self.controller.show_error("No request selected.")
        text = selected.text()
        try:
            requester = text.split(" -> ")[0].strip()  # Strip [ and ]
            filename = text.split(" -> ")[1].split("[")[0]
            self.controller.grant_access(requester, filename)
        except Exception as e:
            self.controller.show_error(f"Failed to parse request: {e}")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropImageFile(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
                self.append_console(f"Uploading dragged image: {path}")
                self.controller.upload(Path(path))
                self.controller.refresh_my_files()
            else:
                self.controller.show_error("Only image files can be dropped.")

    def request_file(self):
        selected = self.peer_files.currentItem()
        if not selected:
            return self.controller.show_error("No file selected.")
        fname = selected.text().split('[')[0].strip()
        requester = self.controller.client.username
        host = self.controller.connect_page.host_input.text()
        port = int(self.controller.connect_page.port_input.text())

        try:
            if not self.controller.client.sock:
                raise Exception("Not connected to peer")
            self.controller.client.sock.sendall(f"REQUEST_REMOTE {fname} {host} 3000 {requester}\n".encode())
            self.controller.append_console(f"[INFO] Request sent for '{fname}'")
        except Exception as e:
            self.controller.show_error(f"Request failed: {e}")

    def download_file(self):
        selected = self.peer_files.currentItem()
        if not selected:
            return self.controller.show_error("No file selected.")
        fname = selected.text()
        fname = selected.text().split('[')[0].strip()
        self.controller.download(fname)

    def append_console(self, msg):
        self.console.append(msg)

    def preview_image(self, filename):
        if self.controller.client.username:
            path = Path(f"downloads-{self.controller.client.username}") / filename
        else:
            path = Path("downloads") / filename
        if path.exists():
            pixmap = QPixmap(str(path))
            if not pixmap.isNull():
                self.image_preview.setPixmap(pixmap.scaled(
                    self.image_preview.size(), Qt.AspectRatioMode.KeepAspectRatio
                ))


# =============================
# Main Controller
# =============================

class P2PFileShareApp(QWidget):
    ROUTE_CONNECT = 0
    ROUTE_GUEST = 1
    ROUTE_HOME = 2

    def __init__(self, peer_port=3000):
        super().__init__()
        self.setWindowTitle("CipherShare — Peer-to-Peer File Transfer")
        self.resize(750, 600)

        self.client = FileShareClient()
        self.peer_port = peer_port
        self.current_route = None

        self.initUI()
        self.start_local_peer()

        # # Make sure home_page is initialized before using it
        # self.auto_refresh_timer = QTimer()
        # self.auto_refresh_timer.timeout.connect(self.refresh_request_list)
        # self.auto_refresh_timer.start(1000)

        # Refresh files on startup
        self.home_page.username = None

    def initUI(self):
        layout = QVBoxLayout()

        # Stacked pages
        self.pages = QStackedWidget()
        self.connect_page = ConnectPage()
        self.guest_page = GuestPage()
        self.home_page = HomePage(controller=self)

        self.pages.addWidget(self.connect_page)
        self.pages.addWidget(self.guest_page)
        self.pages.addWidget(self.home_page)

        # Connect handlers
        self.connect_page.connect_btn.clicked.connect(self.handle_connect)
        self.guest_page.login_btn.clicked.connect(self.handle_login)
        self.guest_page.register_btn.clicked.connect(self.handle_register)

        layout.addWidget(self.pages)
        self.setLayout(layout)

        self.goto_route(self.ROUTE_CONNECT)

    def refresh_request_list(self):
        try:
            if not self.client.sock:
                return
            self.client.sock.sendall(b"LIST_REQUESTS\n")
            resp = self.client._resp()
            if not resp or not resp.startswith("OK"):
                return
            raw_requests = resp[3:].split(',') if len(resp) > 3 else []
            self.home_page.request_list.clear()
            self.home_page.request_list.addItems(raw_requests)
        except Exception as e:
            pass  # Silent fail during auto-refresh

    def grant_access(self, requester, filename):
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(f"GRANT {filename} {requester}\n".encode())
            self.append_console(f"[INFO] Granted '{filename}' to {requester}")
            self.refresh_request_list()
        except Exception as e:
            self.show_error(f"Grant failed: {e}")
            
    def start_local_peer(self):
        from threading import Thread
        Thread(target=self.run_peer_server, daemon=True).start()

    def run_peer_server(self):
        try:
            FileSharePeer(port=self.peer_port).start_peer()
        except Exception as e:
            self.show_error(f"[ERROR] Local peer failed: {e}")

    def goto_route(self, route):
        self.current_route = route
        self.pages.setCurrentIndex(route)

        if route == self.ROUTE_HOME:
            self.update_status_label()
        elif route == self.ROUTE_GUEST:
            self.home_page.status_label.setText("Connected (not logged in)")
        elif route == self.ROUTE_CONNECT:
            self.home_page.status_label.setText("")

    def update_status_label(self):
        if self.client.username and self.client.sock:
            host = self.connect_page.host_input.text()
            port = self.connect_page.port_input.text()
            self.home_page.status_label.setText(f"[{self.client.username}] connected to {host} {port}")
        else:
            self.home_page.status_label.setText("Not logged in")

    def handle_connect(self):
        host = self.connect_page.host_input.text()
        port = int(self.connect_page.port_input.text())
        try:
            self.client.connect(host, port)
            self.append_console(f"[INFO] Connected to {host}:{port}")
            self.goto_route(self.ROUTE_GUEST)
        except Exception as e:
            self.show_error(f"Connection failed: {e}")

    def handle_login(self):
        username = self.prompt_input("Username")
        if not username:
            return
        password = self.prompt_password("Password")
        if not password:
            return
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(f"LOGIN {username}\n".encode())
            resp = self.client._resp()
            if "OK" in resp:
                self.client.sock.sendall(f"PASS {password}\n".encode())
                resp = self.client._resp()
                if "OK" in resp:
                    self.client.username = username
                    self.home_page.username = username
                    Path(f"shared-{self.client.username}").mkdir(exist_ok=True)
                    Path(f"downloads-{self.client.username}").mkdir(exist_ok=True)
                    self.goto_route(self.ROUTE_HOME)
                    self.append_console(f"[INFO] Logged in as {username}")
                    self.update_status_label()  # ✅ Added
                    self.refresh_my_files()
                    self.refresh_peer_files()
                else:
                    self.show_error("Login failed: Invalid password.")
            else:
                self.show_error("Login failed.")
        except Exception as e:
            self.show_error(f"Login error: {e}")

    def handle_register(self):
        username = self.prompt_input("New Username")
        if not username:
            return
        password = self.prompt_password("New Password")
        if not password:
            return
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(f"REGISTER {username} {password}\n".encode())
            resp = self.client._resp()
            self.append_console(f"[INFO] Register: {resp}")
            if "OK" in resp:
                QMessageBox.information(self, "Success", "Registration successful!")
        except Exception as e:
            self.show_error(f"Registration failed: {e}")

    def handle_logout(self, logout_only=True):
        if not self.client.sock:
            return self.show_error("Not connected")

        try:
            self.client.sock.sendall(b"LOGOUT\n")  # Optional: server can ignore
        except:
            pass  # Already disconnected

        if not logout_only:
            try:
                self.client.sock.close()
            except:
                pass
            self.client.sock = None
            self.append_console("[INFO] Disconnected from peer")

        self.client.username = None
        self.home_page.username = None
        self.home_page.status_label.setText("Not logged in")
        self.goto_route(self.ROUTE_GUEST)

    def upload(self, path: Path):
        try:
            shared_dir = Path(f"shared-{self.client.username}")
            shared_dir.mkdir(exist_ok=True)
            encrypted_data = encrypt_file(path.read_bytes())
            payload = encrypted_data[0] + encrypted_data[1]

            with self.client._busy:
                self.client.sock.sendall(f"UPLOAD {path.name} {len(payload)}\n".encode())
                self.client.sock.sendall(payload)
                reply = self.client._readline_raw()
            self.append_console(f"[INFO] Uploaded: {path.name}")
            self.refresh_my_files()
            self.refresh_peer_files()
        except Exception as e:
            self.show_error(f"Upload failed: {e}")

    def download(self, filename: str):
        try:
            self.client.download(filename)
            self.append_console(f"[INFO] Downloaded: {filename}")
            self.home_page.preview_image(filename)
        except Exception as e:
            self.show_error(f"Download failed: {e}")

    def refresh_my_files(self):
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(b"LIST\n")
            resp = self.client._resp()
            if not resp or not resp.startswith("OK"):
                self.show_error(f"Server returned unexpected response: {resp}")
                return
            raw_files = resp[3:].split() if len(resp) > 3 else []
            self.home_page.my_files.clear()
            self.home_page.my_files.addItems(raw_files)
        except Exception as e:
            self.show_error(f"Failed to list files: {e}")

    def refresh_peer_files(self):
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(b"PEERLIST\n")
            resp = self.client._resp()
            if not resp or not resp.startswith("OK"):
                self.show_error(f"Server returned unexpected response: {resp}")
                return
            raw_files = resp[3:].split(',') if len(resp) > 3 else []
            self.home_page.peer_files.clear()
            self.home_page.peer_files.addItems(raw_files)
        except Exception as e:
            self.show_error(f"Failed to list peer files: {e}")

    def show_grant_dialog(self, requester, filename):
        dialog = GrantRequestDialog(requester, filename, self)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.grant_access(requester, filename)

    def grant_access(self, requester, filename):
        try:
            if not self.client.sock:
                raise Exception("Not connected to peer")
            self.client.sock.sendall(f"GRANT {filename} {requester}\n".encode())
            self.append_console(f"[INFO] Granted access to '{filename}' for {requester}")
        except Exception as e:
            self.show_error(f"Grant failed: {e}")

    def show_error(self, msg):
        QMessageBox.critical(self, "Error", msg)

    def append_console(self, msg):
        self.home_page.console.append(msg)

    def prompt_input(self, label):
        text, ok = QInputDialog.getText(self, label, label)
        return text if ok else None

    def prompt_password(self, label):
        text, ok = QInputDialog.getText(self, label, label, echo=QLineEdit.EchoMode.Password)
        return text if ok else None


# =============================
# Entry Point
# =============================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main_gui.py <local-peer-port>")
        sys.exit(1)

    local_port = int(sys.argv[1])
    app = QApplication(sys.argv)
    window = P2PFileShareApp(peer_port=local_port)
    window.show()
    sys.exit(app.exec())