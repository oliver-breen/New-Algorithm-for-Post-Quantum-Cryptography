import base64
import json
import sys
from typing import Any, Dict, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from quantaweave import QuantaWeave, FalconSig


def _encode_bytes(data: bytes, encoding: str) -> str:
    if encoding == "hex":
        return data.hex()
    if encoding == "base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError("Unsupported encoding")


def _decode_bytes(text: str, encoding: str) -> bytes:
    text = text.strip()
    if encoding == "hex":
        return bytes.fromhex(text)
    if encoding == "base64":
        return base64.b64decode(text)
    raise ValueError("Unsupported encoding")


def _show_error(parent: QWidget, message: str) -> None:
    QMessageBox.critical(parent, "QuantaWeave GUI", message)


class LweTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout()

        controls = QHBoxLayout()
        self.level_combo = QComboBox()
        self.level_combo.addItems(["LEVEL1", "LEVEL3", "LEVEL5"])
        controls.addWidget(QLabel("Security level"))
        controls.addWidget(self.level_combo)
        controls.addStretch(1)

        key_box = QGroupBox("Keypair")
        key_layout = QVBoxLayout()
        self.public_key_text = QPlainTextEdit()
        self.public_key_text.setPlaceholderText("Public key (JSON)")
        self.private_key_text = QPlainTextEdit()
        self.private_key_text.setPlaceholderText("Private key (JSON)")
        key_layout.addWidget(QLabel("Public key"))
        key_layout.addWidget(self.public_key_text)
        key_layout.addWidget(QLabel("Private key"))
        key_layout.addWidget(self.private_key_text)
        self.keygen_btn = QPushButton("Generate Keypair")
        self.keygen_btn.clicked.connect(self._on_keygen)
        key_layout.addWidget(self.keygen_btn)
        key_box.setLayout(key_layout)

        crypto_box = QGroupBox("Encrypt / Decrypt")
        crypto_layout = QVBoxLayout()
        self.message_text = QPlainTextEdit()
        self.message_text.setPlaceholderText("Message (UTF-8)")
        self.ciphertext_text = QPlainTextEdit()
        self.ciphertext_text.setPlaceholderText("Ciphertext (JSON)")
        crypto_layout.addWidget(QLabel("Message"))
        crypto_layout.addWidget(self.message_text)
        crypto_layout.addWidget(QLabel("Ciphertext"))
        crypto_layout.addWidget(self.ciphertext_text)

        btn_row = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt")
        self.encrypt_btn.clicked.connect(self._on_encrypt)
        self.decrypt_btn = QPushButton("Decrypt")
        self.decrypt_btn.clicked.connect(self._on_decrypt)
        btn_row.addWidget(self.encrypt_btn)
        btn_row.addWidget(self.decrypt_btn)
        crypto_layout.addLayout(btn_row)
        crypto_box.setLayout(crypto_layout)

        layout.addLayout(controls)
        layout.addWidget(key_box)
        layout.addWidget(crypto_box)
        self.setLayout(layout)

    def _on_keygen(self) -> None:
        try:
            pqc = QuantaWeave(self.level_combo.currentText())
            public_key, private_key = pqc.generate_keypair()
            self.public_key_text.setPlainText(json.dumps(public_key, indent=2))
            self.private_key_text.setPlainText(json.dumps(private_key, indent=2))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_encrypt(self) -> None:
        try:
            message = self.message_text.toPlainText().encode("utf-8")
            public_key = json.loads(self.public_key_text.toPlainText())
            ciphertext = QuantaWeave.encrypt(message, public_key)
            self.ciphertext_text.setPlainText(json.dumps(ciphertext, indent=2))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_decrypt(self) -> None:
        try:
            ciphertext = json.loads(self.ciphertext_text.toPlainText())
            private_key = json.loads(self.private_key_text.toPlainText())
            plaintext = QuantaWeave.decrypt(ciphertext, private_key)
            self.message_text.setPlainText(plaintext.decode("utf-8", errors="replace"))
        except Exception as exc:
            _show_error(self, str(exc))


class HqcTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout()
        controls = QHBoxLayout()
        self.level_combo = QComboBox()
        self.level_combo.addItems(["LEVEL1", "LEVEL3", "LEVEL5"])
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["hex", "base64"])
        controls.addWidget(QLabel("Security level"))
        controls.addWidget(self.level_combo)
        controls.addWidget(QLabel("Encoding"))
        controls.addWidget(self.encoding_combo)
        controls.addStretch(1)

        key_box = QGroupBox("Keypair")
        key_layout = QFormLayout()
        self.public_key_text = QPlainTextEdit()
        self.private_key_text = QPlainTextEdit()
        key_layout.addRow("Public key", self.public_key_text)
        key_layout.addRow("Private key", self.private_key_text)
        self.keygen_btn = QPushButton("Generate Keypair")
        self.keygen_btn.clicked.connect(self._on_keygen)
        key_layout.addRow(self.keygen_btn)
        key_box.setLayout(key_layout)

        kem_box = QGroupBox("Encapsulate / Decapsulate")
        kem_layout = QFormLayout()
        self.ciphertext_text = QPlainTextEdit()
        self.shared_secret_text = QLineEdit()
        self.shared_secret_text.setReadOnly(True)
        self.recovered_secret_text = QLineEdit()
        self.recovered_secret_text.setReadOnly(True)
        kem_layout.addRow("Ciphertext", self.ciphertext_text)
        kem_layout.addRow("Shared secret", self.shared_secret_text)
        kem_layout.addRow("Recovered secret", self.recovered_secret_text)

        btn_row = QHBoxLayout()
        self.encaps_btn = QPushButton("Encapsulate")
        self.encaps_btn.clicked.connect(self._on_encaps)
        self.decaps_btn = QPushButton("Decapsulate")
        self.decaps_btn.clicked.connect(self._on_decaps)
        btn_row.addWidget(self.encaps_btn)
        btn_row.addWidget(self.decaps_btn)
        kem_layout.addRow(btn_row)
        kem_box.setLayout(kem_layout)

        layout.addLayout(controls)
        layout.addWidget(key_box)
        layout.addWidget(kem_box)
        self.setLayout(layout)

    def _on_keygen(self) -> None:
        try:
            pqc = QuantaWeave(self.level_combo.currentText())
            public_key, private_key = pqc.hqc_keypair()
            encoding = self.encoding_combo.currentText()
            self.public_key_text.setPlainText(_encode_bytes(public_key, encoding))
            self.private_key_text.setPlainText(_encode_bytes(private_key, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_encaps(self) -> None:
        try:
            pqc = QuantaWeave(self.level_combo.currentText())
            encoding = self.encoding_combo.currentText()
            public_key = _decode_bytes(self.public_key_text.toPlainText(), encoding)
            ciphertext, shared_secret = pqc.hqc_encapsulate(public_key)
            self.ciphertext_text.setPlainText(_encode_bytes(ciphertext, encoding))
            self.shared_secret_text.setText(_encode_bytes(shared_secret, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_decaps(self) -> None:
        try:
            pqc = QuantaWeave(self.level_combo.currentText())
            encoding = self.encoding_combo.currentText()
            ciphertext = _decode_bytes(self.ciphertext_text.toPlainText(), encoding)
            private_key = _decode_bytes(self.private_key_text.toPlainText(), encoding)
            recovered = pqc.hqc_decapsulate(ciphertext, private_key)
            self.recovered_secret_text.setText(_encode_bytes(recovered, encoding))
        except Exception as exc:
            _show_error(self, str(exc))


class FalconTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout()
        controls = QHBoxLayout()
        self.parameter_combo = QComboBox()
        self.parameter_combo.addItems(["Falcon-512", "Falcon-1024"])
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["hex", "base64"])
        controls.addWidget(QLabel("Parameter set"))
        controls.addWidget(self.parameter_combo)
        controls.addWidget(QLabel("Encoding"))
        controls.addWidget(self.encoding_combo)
        controls.addStretch(1)

        key_box = QGroupBox("Keypair")
        key_layout = QFormLayout()
        self.public_key_text = QPlainTextEdit()
        self.secret_key_text = QPlainTextEdit()
        key_layout.addRow("Public key", self.public_key_text)
        key_layout.addRow("Secret key", self.secret_key_text)
        self.keygen_btn = QPushButton("Generate Keypair")
        self.keygen_btn.clicked.connect(self._on_keygen)
        key_layout.addRow(self.keygen_btn)
        key_box.setLayout(key_layout)

        sign_box = QGroupBox("Sign / Verify")
        sign_layout = QVBoxLayout()
        self.message_text = QPlainTextEdit()
        self.message_text.setPlaceholderText("Message (UTF-8)")
        self.signature_text = QPlainTextEdit()
        self.signature_text.setPlaceholderText("Signature")
        sign_layout.addWidget(QLabel("Message"))
        sign_layout.addWidget(self.message_text)
        sign_layout.addWidget(QLabel("Signature"))
        sign_layout.addWidget(self.signature_text)

        btn_row = QHBoxLayout()
        self.sign_btn = QPushButton("Sign")
        self.sign_btn.clicked.connect(self._on_sign)
        self.verify_btn = QPushButton("Verify")
        self.verify_btn.clicked.connect(self._on_verify)
        btn_row.addWidget(self.sign_btn)
        btn_row.addWidget(self.verify_btn)
        sign_layout.addLayout(btn_row)

        self.verify_result = QLineEdit()
        self.verify_result.setReadOnly(True)
        sign_layout.addWidget(QLabel("Verify result"))
        sign_layout.addWidget(self.verify_result)
        sign_box.setLayout(sign_layout)

        layout.addLayout(controls)
        layout.addWidget(key_box)
        layout.addWidget(sign_box)
        self.setLayout(layout)

    def _get_falcon(self) -> FalconSig:
        return FalconSig(self.parameter_combo.currentText())

    def _on_keygen(self) -> None:
        try:
            falcon = self._get_falcon()
            public_key, secret_key = falcon.keygen()
            encoding = self.encoding_combo.currentText()
            self.public_key_text.setPlainText(_encode_bytes(public_key, encoding))
            self.secret_key_text.setPlainText(_encode_bytes(secret_key, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_sign(self) -> None:
        try:
            falcon = self._get_falcon()
            encoding = self.encoding_combo.currentText()
            secret_key = _decode_bytes(self.secret_key_text.toPlainText(), encoding)
            message = self.message_text.toPlainText().encode("utf-8")
            signature = falcon.sign(secret_key, message)
            self.signature_text.setPlainText(_encode_bytes(signature, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_verify(self) -> None:
        try:
            falcon = self._get_falcon()
            encoding = self.encoding_combo.currentText()
            public_key = _decode_bytes(self.public_key_text.toPlainText(), encoding)
            signature = _decode_bytes(self.signature_text.toPlainText(), encoding)
            message = self.message_text.toPlainText().encode("utf-8")
            valid = falcon.verify(public_key, message, signature)
            self.verify_result.setText("valid" if valid else "invalid")
        except Exception as exc:
            _show_error(self, str(exc))


class QuantaWeaveWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("QuantaWeave GUI")
        self.resize(900, 700)

        tabs = QTabWidget()
        tabs.addTab(LweTab(), "LWE")
        tabs.addTab(HqcTab(), "HQC KEM")
        tabs.addTab(FalconTab(), "Falcon")
        self.setCentralWidget(tabs)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = QuantaWeaveWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
