"""
Plugin entry point for Secure File Share System.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QFrame, QTabWidget
)

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.logger import get_logger

from .share import encrypt_file, decrypt_file, generate_strong_password

logger = get_logger("hacks.secure_file_share")

PLUGIN_METADATA = {
    "id": "hacks.secure_file_share",
    "name": "Secure File Share System",
    "category": "hacks",
    "description": "Encrypts files with a password before sharing, using authenticated AES encryption.",
    "icon": "lock",
}


class SecureFileShareWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Secure File Share System")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Encrypt a file with a password before sending it anywhere (email, USB, cloud). "
            "Uses AES encryption with built-in tamper detection — wrong password or a "
            "corrupted file will be clearly rejected, never silently produce garbage."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_encrypt_tab(), "Encrypt a File")
        tabs.addTab(self._build_decrypt_tab(), "Decrypt a File")
        root.addWidget(tabs, stretch=1)

        result_frame = QFrame()
        result_frame.setStyleSheet(f"background:{PANEL_BG}; border-radius:10px; padding:14px;")
        result_layout = QVBoxLayout(result_frame)
        self.result_label = QLabel("No operation performed yet.")
        self.result_label.setStyleSheet(f"color:{MUTED};")
        self.result_label.setWordWrap(True)
        result_layout.addWidget(self.result_label)
        root.addWidget(result_frame)

    # ---------- Tab 1: Encrypt ----------

    def _build_encrypt_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        file_row = QHBoxLayout()
        self.enc_file_btn = QPushButton("Choose File to Encrypt...")
        self.enc_file_btn.clicked.connect(self.on_choose_encrypt_file)
        self.enc_file_label = QLabel("No file selected.")
        self.enc_file_label.setStyleSheet(f"color:{MUTED};")
        file_row.addWidget(self.enc_file_btn)
        file_row.addWidget(self.enc_file_label, stretch=1)
        layout.addLayout(file_row)
        self.enc_file_path = None

        pw_row = QHBoxLayout()
        self.enc_password = QLineEdit()
        self.enc_password.setPlaceholderText("Choose a password...")
        self.enc_password.setEchoMode(QLineEdit.EchoMode.Password)
        gen_btn = QPushButton("Generate Strong Password")
        gen_btn.clicked.connect(self.on_generate_password)
        pw_row.addWidget(self.enc_password, stretch=1)
        pw_row.addWidget(gen_btn)
        layout.addLayout(pw_row)

        self.show_pw_label = QLabel("")
        self.show_pw_label.setStyleSheet(f"color:{ACCENT}; font-family: Consolas, monospace;")
        self.show_pw_label.setWordWrap(True)
        layout.addWidget(self.show_pw_label)

        warn = QLabel(
            "⚠ Remember this password separately — if you lose it, the file cannot be recovered."
        )
        warn.setStyleSheet(f"color:{WARN}; font-size: 11px;")
        layout.addWidget(warn)

        encrypt_btn = QPushButton("Encrypt File")
        encrypt_btn.clicked.connect(self.on_encrypt)
        layout.addWidget(encrypt_btn)
        layout.addStretch(1)
        return tab

    def on_choose_encrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to encrypt")
        if not path:
            return
        self.enc_file_path = path
        self.enc_file_label.setText(os.path.basename(path))

    def on_generate_password(self):
        pw = generate_strong_password()
        self.enc_password.setText(pw)
        self.enc_password.setEchoMode(QLineEdit.EchoMode.Normal)
        self.show_pw_label.setText(f"Generated: {pw}")

    def on_encrypt(self):
        if not self.enc_file_path:
            self.result_label.setText("Choose a file first.")
            return
        password = self.enc_password.text()
        if not password:
            self.result_label.setText("Enter or generate a password first.")
            return

        default_out = self.enc_file_path + ".rpx"
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save encrypted file as...", default_out, "Rupux Encrypted (*.rpx)"
        )
        if not output_path:
            return

        result = encrypt_file(self.enc_file_path, output_path, password)
        self.result_label.setText(result.message + (f"\nSaved to: {output_path}" if result.success else ""))

        self.event_bus.publish(SecurityEvent(
            source="hacks.secure_file_share",
            category="hacks",
            title="File encrypted for sharing" if result.success else "File encryption failed",
            severity="info" if result.success else "medium",
            details={"output_path": output_path if result.success else None},
        ))
        logger.info(result.message)

    # ---------- Tab 2: Decrypt ----------

    def _build_decrypt_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        file_row = QHBoxLayout()
        self.dec_file_btn = QPushButton("Choose .rpx File...")
        self.dec_file_btn.clicked.connect(self.on_choose_decrypt_file)
        self.dec_file_label = QLabel("No file selected.")
        self.dec_file_label.setStyleSheet(f"color:{MUTED};")
        file_row.addWidget(self.dec_file_btn)
        file_row.addWidget(self.dec_file_label, stretch=1)
        layout.addLayout(file_row)
        self.dec_file_path = None

        self.dec_password = QLineEdit()
        self.dec_password.setPlaceholderText("Enter the password...")
        self.dec_password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.dec_password)

        decrypt_btn = QPushButton("Decrypt File")
        decrypt_btn.clicked.connect(self.on_decrypt)
        layout.addWidget(decrypt_btn)
        layout.addStretch(1)
        return tab

    def on_choose_decrypt_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose an encrypted file", "", "Rupux Encrypted (*.rpx);;All Files (*)"
        )
        if not path:
            return
        self.dec_file_path = path
        self.dec_file_label.setText(os.path.basename(path))

    def on_decrypt(self):
        if not self.dec_file_path:
            self.result_label.setText("Choose an encrypted file first.")
            return
        password = self.dec_password.text()
        if not password:
            self.result_label.setText("Enter the password first.")
            return

        default_out = self.dec_file_path.removesuffix(".rpx") if self.dec_file_path.endswith(".rpx") \
            else self.dec_file_path + ".decrypted"
        output_path, _ = QFileDialog.getSaveFileName(self, "Save decrypted file as...", default_out)
        if not output_path:
            return

        result = decrypt_file(self.dec_file_path, output_path, password)
        self.result_label.setText(result.message + (f"\nSaved to: {output_path}" if result.success else ""))

        self.event_bus.publish(SecurityEvent(
            source="hacks.secure_file_share",
            category="hacks",
            title="File decrypted successfully" if result.success else "File decryption failed (wrong password or tampered file)",
            severity="info" if result.success else "medium",
            details={"output_path": output_path if result.success else None},
        ))
        logger.info(result.message)


def get_widget(event_bus):
    return SecureFileShareWidget(event_bus)
