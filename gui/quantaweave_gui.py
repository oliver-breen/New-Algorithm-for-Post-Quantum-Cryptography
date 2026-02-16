import os
import sys

if os.name == 'nt':
    try:
        # Add current directory and quantaweave subdirectory to DLL search path
        os.add_dll_directory(os.getcwd())
        # Also try adding the directory where this script is, if different
        os.add_dll_directory(os.path.dirname(os.path.abspath(__file__)))
        # And the package directory
        os.add_dll_directory(os.path.join(os.getcwd(), 'quantaweave'))
    except AttributeError:
        pass

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
from pqcrypto.pqcrypto_suite import PQCryptoSuite

from quantaweave import QuantaWeave, FalconSig
from quantaweave.woven_algorithm import QuantaWeaveAlgorithm

class UnifiedPQTab(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        kem_row = QHBoxLayout()
        self.kem_combo = QComboBox(); self.kem_combo.addItems(["kyber", "hqc"])
        self.sig_combo = QComboBox(); self.sig_combo.addItems(["dilithium", "falcon"])
        self.level_combo = QComboBox(); self.level_combo.addItems(["LEVEL1", "LEVEL3", "LEVEL5"])
        kem_row.addWidget(QLabel("KEM")); kem_row.addWidget(self.kem_combo)
        kem_row.addWidget(QLabel("Signature")); kem_row.addWidget(self.sig_combo)
        kem_row.addWidget(QLabel("Level")); kem_row.addWidget(self.level_combo)
        kem_row.addStretch(1)
        layout.addLayout(kem_row)

        # KEM Keypair
        self.kem_pk = QLineEdit(); self.kem_sk = QLineEdit()
        kem_btn = QPushButton("Generate KEM Keypair"); kem_btn.clicked.connect(self._on_kem_keygen)
        layout.addWidget(QLabel("KEM Public Key")); layout.addWidget(self.kem_pk)
        layout.addWidget(QLabel("KEM Private Key")); layout.addWidget(self.kem_sk)
        layout.addWidget(kem_btn)

        # Encaps/Decaps
        self.kem_ct = QLineEdit(); self.kem_ss = QLineEdit(); self.kem_rec = QLineEdit()
        kem_enc_btn = QPushButton("Encapsulate"); kem_enc_btn.clicked.connect(self._on_kem_encaps)
        kem_dec_btn = QPushButton("Decapsulate"); kem_dec_btn.clicked.connect(self._on_kem_decaps)
        layout.addWidget(QLabel("KEM Ciphertext")); layout.addWidget(self.kem_ct)
        layout.addWidget(QLabel("KEM Shared Secret")); layout.addWidget(self.kem_ss)
        layout.addWidget(QLabel("KEM Recovered Secret")); layout.addWidget(self.kem_rec)
        layout.addWidget(kem_enc_btn); layout.addWidget(kem_dec_btn)

        # Message Encryption (KEM)
        self.kem_msg_in = QLineEdit(); self.kem_msg_in.setPlaceholderText("Message")
        self.kem_msg_enc = QLineEdit(); self.kem_msg_enc.setPlaceholderText("Encrypted")
        self.kem_msg_out = QLineEdit(); self.kem_msg_out.setPlaceholderText("Decrypted")
        kem_msg_enc_btn = QPushButton("Encrypt Msg"); kem_msg_enc_btn.clicked.connect(self._on_kem_encrypt_msg)
        kem_msg_dec_btn = QPushButton("Decrypt Msg"); kem_msg_dec_btn.clicked.connect(self._on_kem_decrypt_msg)
        layout.addWidget(QLabel("Message Encryption (using Shared Secret)"))
        layout.addWidget(self.kem_msg_in)
        layout.addWidget(self.kem_msg_enc)
        layout.addWidget(self.kem_msg_out)
        hlayout = QHBoxLayout()
        hlayout.addWidget(kem_msg_enc_btn); hlayout.addWidget(kem_msg_dec_btn)
        layout.addLayout(hlayout)

        # Signature Keypair
        self.sig_pk = QLineEdit(); self.sig_sk = QLineEdit()
        sig_btn = QPushButton("Generate Sig Keypair"); sig_btn.clicked.connect(self._on_sig_keygen)
        layout.addWidget(QLabel("Signature Public Key")); layout.addWidget(self.sig_pk)
        layout.addWidget(QLabel("Signature Secret Key")); layout.addWidget(self.sig_sk)
        layout.addWidget(sig_btn)

        # Sign/Verify
        self.sig_msg = QLineEdit(); self.sig_sig = QLineEdit(); self.sig_result = QLineEdit(); self.sig_result.setReadOnly(True)
        sign_btn = QPushButton("Sign"); sign_btn.clicked.connect(self._on_sign)
        verify_btn = QPushButton("Verify"); verify_btn.clicked.connect(self._on_verify)
        layout.addWidget(QLabel("Message to Sign")); layout.addWidget(self.sig_msg)
        layout.addWidget(QLabel("Signature")); layout.addWidget(self.sig_sig)
        layout.addWidget(sign_btn); layout.addWidget(verify_btn)
        layout.addWidget(QLabel("Verify Result")); layout.addWidget(self.sig_result)
        self.setLayout(layout)

    def _suite(self):
        return PQCryptoSuite(
            kem=self.kem_combo.currentText(),
            sig=self.sig_combo.currentText(),
            level=self.level_combo.currentText(),
        )
    def _on_kem_keygen(self):
        suite = self._suite()
        pk, sk = suite.kem_keypair()
        self.kem_pk.setText(str(pk)); self.kem_sk.setText(str(sk))

    def _on_kem_encaps(self):
        suite = self._suite()
        ct, ss = suite.kem_encapsulate(self.kem_pk.text())
        self.kem_ct.setText(str(ct)); self.kem_ss.setText(str(ss))

    def _on_kem_decaps(self):
        suite = self._suite()
        rec = suite.kem_decapsulate(self.kem_ct.text(), self.kem_sk.text())
        self.kem_rec.setText(str(rec))
    
    def _on_kem_encrypt_msg(self):
        ss = self.kem_ss.text()
        msg = self.kem_msg_in.text()
        if not ss or not msg: return
        # Simple XOR for demonstration
        enc = "".join([chr(ord(a) ^ ord(b)) for a, b in zip(msg, ss * (len(msg)//len(ss) + 1))])
        self.kem_msg_enc.setText(base64.b64encode(enc.encode('latin1')).decode('ascii'))

    def _on_kem_decrypt_msg(self):
        ss = self.kem_rec.text()
        if not ss: ss = self.kem_ss.text()
        enc_b64 = self.kem_msg_enc.text()
        if not ss or not enc_b64: return
        try:
            enc = base64.b64decode(enc_b64).decode('latin1')
            dec = "".join([chr(ord(a) ^ ord(b)) for a, b in zip(enc, ss * (len(enc)//len(ss) + 1))])
            self.kem_msg_out.setText(dec)
        except:
            self.kem_msg_out.setText("Error")

    def _on_sig_keygen(self):
        suite = self._suite()
        pk, sk = suite.sig_keypair()
        self.sig_pk.setText(str(pk)); self.sig_sk.setText(str(sk))
    def _on_sign(self):
        suite = self._suite()
        sig = suite.sign(self.sig_sk.text(), self.sig_msg.text().encode("utf-8"))
        self.sig_sig.setText(str(sig))
    def _on_verify(self):
        suite = self._suite()
        valid = suite.verify(self.sig_pk.text(), self.sig_msg.text().encode("utf-8"), self.sig_sig.text())
        self.sig_result.setText("valid" if valid else "invalid")
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
from quantaweave.woven_algorithm import QuantaWeaveAlgorithm


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
        self.decrypted_text = QPlainTextEdit()
        self.decrypted_text.setPlaceholderText("Decrypted Message")
        self.decrypted_text.setReadOnly(True)
        
        crypto_layout.addWidget(QLabel("Message"))
        crypto_layout.addWidget(self.message_text)
        crypto_layout.addWidget(QLabel("Ciphertext"))
        crypto_layout.addWidget(self.ciphertext_text)
        crypto_layout.addWidget(QLabel("Decrypted Output"))
        crypto_layout.addWidget(self.decrypted_text)

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
            self.decrypted_text.setPlainText(plaintext.decode("utf-8", errors="replace"))
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
        
        # Message Encryption using Shared Secret
        self.kem_msg_in = QLineEdit()
        self.kem_msg_in.setPlaceholderText("Message to encrypt with shared secret")
        self.kem_msg_enc = QLineEdit()
        self.kem_msg_enc.setReadOnly(True)
        self.kem_msg_out = QLineEdit()
        self.kem_msg_out.setReadOnly(True)
        
        kem_msg_btn_row = QHBoxLayout()
        self.kem_encrypt_btn = QPushButton("Encrypt Message")
        self.kem_encrypt_btn.clicked.connect(self._on_kem_encrypt_msg)
        self.kem_decrypt_btn = QPushButton("Decrypt Message")
        self.kem_decrypt_btn.clicked.connect(self._on_kem_decrypt_msg)
        kem_msg_btn_row.addWidget(self.kem_encrypt_btn)
        kem_msg_btn_row.addWidget(self.kem_decrypt_btn)
        
        kem_layout.addRow("Message", self.kem_msg_in)
        kem_layout.addRow("Encrypted Message", self.kem_msg_enc)
        kem_layout.addRow("Decrypted Message", self.kem_msg_out)
        kem_layout.addRow(kem_msg_btn_row)
        
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
            shared_secret = pqc.hqc_decapsulate(ciphertext, private_key)
            self.recovered_secret_text.setText(_encode_bytes(shared_secret, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_kem_encrypt_msg(self) -> None:
        try:
            ss_hex = self.shared_secret_text.text()
            if not ss_hex:
                _show_error(self, "No shared secret available")
                return
            # Use simple XOR with repeated key for demonstration
            # In production this should be AES-GCM or similar
            encoding = self.encoding_combo.currentText()
            ss_bytes = _decode_bytes(ss_hex, encoding)
            msg_bytes = self.kem_msg_in.text().encode("utf-8")
            
            enc_bytes = bytearray()
            for i, b in enumerate(msg_bytes):
                enc_bytes.append(b ^ ss_bytes[i % len(ss_bytes)])
            
            self.kem_msg_enc.setText(_encode_bytes(bytes(enc_bytes), encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_kem_decrypt_msg(self) -> None:
        try:
            ss_hex = self.recovered_secret_text.text()
            if not ss_hex:
                # If recovered is empty, try shared secret (for testing)
                ss_hex = self.shared_secret_text.text()
                
            if not ss_hex:
                _show_error(self, "No shared/recovered secret available")
                return

            encoding = self.encoding_combo.currentText()
            ss_bytes = _decode_bytes(ss_hex, encoding)
            enc_str = self.kem_msg_enc.text()
            enc_bytes = _decode_bytes(enc_str, encoding)
            
            dec_bytes = bytearray()
            for i, b in enumerate(enc_bytes):
                dec_bytes.append(b ^ ss_bytes[i % len(ss_bytes)])
            
            self.kem_msg_out.setText(dec_bytes.decode("utf-8", errors="replace"))
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
            
            if all(b == 0 for b in signature):
                _show_error(self, "Warning: Generated signature is all zeros. Implementation may be incomplete.")
                
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


class WovenTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.algo = QuantaWeaveAlgorithm()
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout()
        
        # Info
        layout.addWidget(QLabel("<b>Hybrid QuantaWeave Algorithm</b><br>Combines Kyber-768 + HQC-128 (KEM) and Dilithium-3 + Falcon-1024 (Signature)"))

        # Controls
        controls = QHBoxLayout()
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(["base64", "hex"]) # Default to base64 for large blobs
        controls.addWidget(QLabel("Encoding"))
        controls.addWidget(self.encoding_combo)
        controls.addStretch(1)
        layout.addLayout(controls)

        # Keypair
        key_box = QGroupBox("Unified Keypair")
        key_layout = QFormLayout()
        self.pk_text = QPlainTextEdit()
        self.sk_text = QPlainTextEdit()
        self.pk_text.setMaximumHeight(60)
        self.sk_text.setMaximumHeight(60)
        key_layout.addRow("Public Key (Blob)", self.pk_text)
        key_layout.addRow("Secret Key (Blob)", self.sk_text)
        
        keygen_btn = QPushButton("Generate Hybrid Keypair")
        keygen_btn.clicked.connect(self._on_keygen)
        key_layout.addRow(keygen_btn)
        key_box.setLayout(key_layout)
        layout.addWidget(key_box)

        # Operations Tabs (KEM vs Sign)
        ops_tabs = QTabWidget()
        
        # KEM Tab
        kem_widget = QWidget()
        kem_layout = QFormLayout()
        
        self.kem_ct = QPlainTextEdit(); self.kem_ct.setMaximumHeight(50)
        self.kem_ss = QLineEdit(); self.kem_ss.setReadOnly(True)
        self.kem_rec = QLineEdit(); self.kem_rec.setReadOnly(True)
        
        encaps_btn = QPushButton("Encapsulate (using PK)")
        encaps_btn.clicked.connect(self._on_encaps)
        decaps_btn = QPushButton("Decapsulate (using CT + SK)")
        decaps_btn.clicked.connect(self._on_decaps)
        
        kem_layout.addRow("Ciphertext", self.kem_ct)
        kem_layout.addRow(encaps_btn)
        kem_layout.addRow("Shared Secret", self.kem_ss)
        kem_layout.addRow("Recovered Secret", self.kem_rec)
        kem_layout.addRow(decaps_btn)
        kem_widget.setLayout(kem_layout)
        ops_tabs.addTab(kem_widget, "Hybrid KEM")

        # Sign Tab
        sign_widget = QWidget()
        sign_layout = QFormLayout()
        
        self.msg_in = QLineEdit(); self.msg_in.setPlaceholderText("Message to sign")
        self.sig_out = QPlainTextEdit(); self.sig_out.setMaximumHeight(50)
        self.verify_res = QLineEdit(); self.verify_res.setReadOnly(True)
        
        sign_btn = QPushButton("Sign (using SK)")
        sign_btn.clicked.connect(self._on_sign)
        verify_btn = QPushButton("Verify (using Sig + PK)")
        verify_btn.clicked.connect(self._on_verify)
        
        sign_layout.addRow("Message", self.msg_in)
        sign_layout.addRow("Signature", self.sig_out)
        sign_layout.addRow(sign_btn)
        sign_layout.addRow("Verification", self.verify_res)
        sign_layout.addRow(verify_btn)
        sign_widget.setLayout(sign_layout)
        ops_tabs.addTab(sign_widget, "Hybrid Signature")

        layout.addWidget(ops_tabs)
        self.setLayout(layout)

    def _on_keygen(self) -> None:
        try:
            encoding = self.encoding_combo.currentText()
            pk, sk = self.algo.generate_keypair()
            self.pk_text.setPlainText(_encode_bytes(pk, encoding))
            self.sk_text.setPlainText(_encode_bytes(sk, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_encaps(self) -> None:
        try:
            encoding = self.encoding_combo.currentText()
            pk = _decode_bytes(self.pk_text.toPlainText(), encoding)
            ct, ss = self.algo.encapsulate(pk)
            self.kem_ct.setPlainText(_encode_bytes(ct, encoding))
            self.kem_ss.setText(_encode_bytes(ss, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_decaps(self) -> None:
        try:
            encoding = self.encoding_combo.currentText()
            ct = _decode_bytes(self.kem_ct.toPlainText(), encoding)
            sk = _decode_bytes(self.sk_text.toPlainText(), encoding)
            ss = self.algo.decapsulate(ct, sk)
            self.kem_rec.setText(_encode_bytes(ss, encoding))
        except Exception as exc:
            _show_error(self, str(exc))
            
    def _on_sign(self) -> None:
        try:
            encoding = self.encoding_combo.currentText()
            msg = self.msg_in.text().encode("utf-8")
            sk = _decode_bytes(self.sk_text.toPlainText(), encoding)
            sig = self.algo.sign(msg, sk)
            self.sig_out.setPlainText(_encode_bytes(sig, encoding))
        except Exception as exc:
            _show_error(self, str(exc))

    def _on_verify(self) -> None:
        try:
            encoding = self.encoding_combo.currentText()
            msg = self.msg_in.text().encode("utf-8")
            sig = _decode_bytes(self.sig_out.toPlainText(), encoding)
            pk = _decode_bytes(self.pk_text.toPlainText(), encoding)
            valid = self.algo.verify(msg, sig, pk)
            self.verify_res.setText("Valid" if valid else "Invalid")
        except Exception as exc:
            _show_error(self, str(exc))


class QuantaWeaveWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("QuantaWeave GUI")
        self.resize(900, 700)

        tabs = QTabWidget()
        tabs.addTab(WovenTab(), "Woven Algorithm")
        tabs.addTab(LweTab(), "LWE")
        tabs.addTab(HqcTab(), "HQC KEM")
        tabs.addTab(FalconTab(), "Falcon")
        tabs.addTab(UnifiedPQTab(), "PQ Suite")
        self.setCentralWidget(tabs)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = QuantaWeaveWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
