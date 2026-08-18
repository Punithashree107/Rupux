"""
Plugin entry point for Cryptanalysis.
Follows the standard Rupux plugin contract:
  PLUGIN_METADATA dict + get_widget(event_bus) -> QWidget
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QFrame, QTabWidget, QPlainTextEdit
)
from PyQt6.QtCore import Qt

from core.config import TEXT, MUTED, PANEL_BG, ACCENT, DANGER, WARN
from core.event_bus import SecurityEvent
from core.logger import get_logger

from .analyzer import (
    crack_caesar, crack_vigenere, xor_bruteforce, parse_input_bytes,
    detect_and_decode, identify_hash, check_common_password_hash,
)

logger = get_logger("hacks.cryptanalysis")

PLUGIN_METADATA = {
    "id": "hacks.cryptanalysis",
    "name": "Cryptanalysis",
    "category": "hacks",
    "description": "Breaks classical ciphers, brute-forces XOR keys, detects encodings, and identifies hash types.",
    "icon": "key",
}


def _panel_textedit(readonly=True) -> QPlainTextEdit:
    box = QPlainTextEdit()
    box.setReadOnly(readonly)
    box.setStyleSheet(
        f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px; padding:8px; font-family: Consolas, monospace;"
    )
    return box


class CryptanalysisWidget(QWidget):
    def __init__(self, event_bus):
        super().__init__()
        self.event_bus = event_bus
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Cryptanalysis")
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color:{TEXT};")
        subtitle = QLabel(
            "Classical cryptanalysis techniques — frequency analysis, brute force, and pattern "
            "matching. Works on weak/legacy schemes only, which is the point: it shows exactly "
            "why they should never protect anything sensitive today."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color:{MUTED}; margin-bottom: 10px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        tabs = QTabWidget()
        tabs.addTab(self._build_classical_tab(), "Caesar / Vigenère")
        tabs.addTab(self._build_xor_tab(), "XOR Breaker")
        tabs.addTab(self._build_encoding_tab(), "Encoding Detector")
        tabs.addTab(self._build_hash_tab(), "Hash Identifier")
        root.addWidget(tabs, stretch=1)

    # ---------- Tab 1: Caesar / Vigenere ----------

    def _build_classical_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        layout.addWidget(QLabel("Ciphertext:"))
        self.classical_input = QTextEdit()
        self.classical_input.setFixedHeight(80)
        self.classical_input.setStyleSheet(f"background:{PANEL_BG}; color:{TEXT}; border-radius:8px; padding:6px;")
        layout.addWidget(self.classical_input)

        btn_row = QHBoxLayout()
        caesar_btn = QPushButton("Crack as Caesar Cipher")
        caesar_btn.clicked.connect(self.on_crack_caesar)
        vigenere_btn = QPushButton("Crack as Vigenère Cipher")
        vigenere_btn.clicked.connect(self.on_crack_vigenere)
        btn_row.addWidget(caesar_btn)
        btn_row.addWidget(vigenere_btn)
        layout.addLayout(btn_row)

        layout.addWidget(QLabel("Top candidates (best statistical match first):"))
        self.classical_output = _panel_textedit()
        layout.addWidget(self.classical_output, stretch=1)
        return tab

    def on_crack_caesar(self):
        text = self.classical_input.toPlainText()
        if not text.strip():
            self.classical_output.setPlainText("Enter some ciphertext first.")
            return
        results = crack_caesar(text, top_n=5)
        lines = []
        for r in results:
            lines.append(f"[shift={r.shift:2}]  score={r.score:6.1f}\n  {r.plaintext}\n")
        self.classical_output.setPlainText("\n".join(lines))
        self._publish("Caesar cipher cracked", "info", {"best_shift": results[0].shift})

    def on_crack_vigenere(self):
        text = self.classical_input.toPlainText()
        if not text.strip():
            self.classical_output.setPlainText("Enter some ciphertext first.")
            return
        results = crack_vigenere(text, top_n=5)
        if not results:
            self.classical_output.setPlainText(
                "Not enough letters for reliable statistical analysis. "
                "Vigenère cracking needs a reasonably long ciphertext (50+ letters)."
            )
            return
        lines = []
        for r in results:
            lines.append(f"[key='{r.key}'  length={r.key_length}]  score={r.score:6.1f}\n  {r.plaintext}\n")
        note = (
            "\nNote: shorter ciphertexts often produce several plausible candidates — "
            "the true key length usually divides evenly into the top guesses."
        )
        self.classical_output.setPlainText("\n".join(lines) + note)
        self._publish("Vigenère cipher cracked", "info", {"best_key": results[0].key})

    # ---------- Tab 2: XOR ----------

    def _build_xor_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        layout.addWidget(QLabel("Ciphertext (hex string, or raw text):"))
        self.xor_input = QLineEdit()
        self.xor_input.setPlaceholderText("e.g. 232f232b6720... or paste raw bytes as text")
        layout.addWidget(self.xor_input)

        btn = QPushButton("Brute-force Single-Byte XOR Key")
        btn.clicked.connect(self.on_crack_xor)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Top candidates:"))
        self.xor_output = _panel_textedit()
        layout.addWidget(self.xor_output, stretch=1)
        return tab

    def on_crack_xor(self):
        text = self.xor_input.text()
        if not text.strip():
            self.xor_output.setPlainText("Enter ciphertext first (hex or raw text).")
            return
        data = parse_input_bytes(text)
        results = xor_bruteforce(data, top_n=5)
        lines = []
        for r in results:
            printable = r.plaintext.replace("\n", "\\n")
            lines.append(f"[key=0x{r.key:02x} ({r.key:3})]  score={r.score:6.1f}\n  {printable}\n")
        self.xor_output.setPlainText("\n".join(lines))
        self._publish("XOR single-byte key recovered", "info", {"best_key": f"0x{results[0].key:02x}"})

    # ---------- Tab 3: Encoding detector ----------

    def _build_encoding_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        layout.addWidget(QLabel("Text to analyze:"))
        self.encoding_input = QLineEdit()
        self.encoding_input.setPlaceholderText("Paste Base64, Hex, Binary, or ROT13 text...")
        self.encoding_input.textChanged.connect(self.on_encoding_changed)
        layout.addWidget(self.encoding_input)

        layout.addWidget(QLabel("Detected decodings:"))
        self.encoding_output = _panel_textedit()
        layout.addWidget(self.encoding_output, stretch=1)
        return tab

    def on_encoding_changed(self, text: str):
        if not text.strip():
            self.encoding_output.setPlainText("")
            return
        steps = detect_and_decode(text)
        lines = []
        for step in steps:
            marker = "✓" if step.success else "✗"
            lines.append(f"{marker} {step.label}:\n  {step.result}\n")
        self.encoding_output.setPlainText("\n".join(lines) if lines else "No recognizable encoding pattern.")

    # ---------- Tab 4: Hash identifier ----------

    def _build_hash_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 16, 4, 4)

        layout.addWidget(QLabel("Hash string:"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Paste a hash value...")
        layout.addWidget(self.hash_input)

        btn = QPushButton("Identify Hash")
        btn.clicked.connect(self.on_identify_hash)
        layout.addWidget(btn)

        layout.addWidget(QLabel("Result:"))
        self.hash_output = _panel_textedit()
        layout.addWidget(self.hash_output, stretch=1)

        note = QLabel(
            "Only checks against a small list of well-known common passwords — "
            "not a general-purpose hash cracker."
        )
        note.setStyleSheet(f"color:{MUTED}; font-size: 11px;")
        layout.addWidget(note)
        return tab

    def on_identify_hash(self):
        text = self.hash_input.text().strip()
        if not text:
            self.hash_output.setPlainText("Enter a hash first.")
            return
        possibilities = identify_hash(text)
        lines = ["Possible algorithm(s):"] + [f"  • {p}" for p in possibilities]

        common_match = check_common_password_hash(text)
        if common_match:
            lines.append("")
            lines.append(f"⚠ {common_match}")
            self._publish(
                "Hash matches a common password", "high",
                {"hash_prefix": text[:12]},
            )
        self.hash_output.setPlainText("\n".join(lines))

    # ---------- shared ----------

    def _publish(self, title: str, severity: str, details: dict):
        self.event_bus.publish(SecurityEvent(
            source="hacks.cryptanalysis",
            category="hacks",
            title=title,
            severity=severity,
            details=details,
        ))
        logger.info(title)


def get_widget(event_bus):
    return CryptanalysisWidget(event_bus)
