import sys
import os
import secrets
import hashlib

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QPushButton, QFileDialog, QLineEdit, QMessageBox,
    QProgressBar, QRadioButton, QButtonGroup, QComboBox, QInputDialog, QTabWidget
)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from argon2 import low_level

CHUNK_SIZE = 1024 * 1024  # 1 MB chunk for GCM mode

def pkcs7_pad(data: bytes, block_size=16) -> bytes:
    """Apply PKCS#7 padding for CBC mode."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes, block_size=16) -> bytes:
    """Remove PKCS#7 padding."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 padded data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding bytes.")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("Padding check failed.")
    return data[:-pad_len]

def check_password_strength(passphrase: str) -> bool:
    """Improved password strength check:
    - At least 12 characters
    - Contains uppercase, lowercase, digits, and symbols
    """
    if len(passphrase) < 12:
        return False
    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~" for c in passphrase)
    return has_upper and has_lower and has_digit and has_symbol

def derive_kek(passphrase: str, salt: bytes, iterations: int = 2, memory_cost: int = 102400, parallelism: int = 8) -> bytes:
    """Derive the Key Encryption Key (KEK) from the user's passphrase using Argon2id."""
    return low_level.hash_secret_raw(
        secret=passphrase.encode('utf-8'),
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=low_level.Type.ID
    )

class PassphraseDialog:
    """Static method for prompting user passphrase via QInputDialog."""
    @staticmethod
    def get_passphrase(title: str, prompt: str):
        passphrase, ok = QInputDialog.getText(None, title, prompt, echo=QLineEdit.Password)
        return passphrase, ok

class KeyManager:
    """
    Manages AES key generation, saving, and loading in two modes:
      1) standard: raw 32-byte key
      2) passphrase: AES-GCM-encrypted key [nonce(12)+tag(16)+enc(32)+salt(32)]
    """
    @staticmethod
    def generate_key() -> bytes:
        return secrets.token_bytes(32)  # 32-byte AES key

    @staticmethod
    def save_key(key: bytes, file_path: str, mode: str):
        if mode == "standard":
            with open(file_path, "wb") as f:
                f.write(key)
        else:
            passphrase, ok = PassphraseDialog.get_passphrase(
                "Save Key (Passphrase)",
                "Enter passphrase (>=12 chars, must include uppercase, lowercase, digits & symbols):"
            )
            if not ok or not passphrase:
                raise ValueError("No passphrase provided; cannot save key.")
            if not check_password_strength(passphrase):
                raise ValueError("Passphrase is too weak.")

            salt = secrets.token_bytes(32)  # Increased salt size to 32 bytes
            kek = derive_kek(passphrase, salt)
            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            enc_key = encryptor.update(key) + encryptor.finalize()
            tag = encryptor.tag

            with open(file_path, "wb") as f:
                f.write(nonce)
                f.write(tag)
                f.write(enc_key)
                f.write(salt)

    @staticmethod
    def load_key(file_path: str, mode: str) -> bytes:
        if mode == "standard":
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) != 32:
                raise ValueError("In standard mode, .key must be exactly 32 bytes.")
            return data
        else:
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) < (12 + 16 + 32 + 32):
                raise ValueError("Invalid passphrase-encrypted .key file (too small).")

            nonce = data[:12]
            tag = data[12:28]
            enc_key = data[28:-32]
            salt = data[-32:]

            passphrase, ok = PassphraseDialog.get_passphrase(
                "Load Key (Passphrase)",
                "Enter passphrase to decrypt key:"
            )
            if not ok or not passphrase:
                raise ValueError("No passphrase provided; cannot load key.")

            kek = derive_kek(passphrase, salt)
            cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            raw_key = decryptor.update(enc_key) + decryptor.finalize()
            if len(raw_key) != 32:
                raise ValueError("Decrypted key is not 32 bytes. Possibly wrong passphrase.")
            return raw_key

# ------------------------------------------------------------------------
# Encryption / Decryption Thread Classes
# Each handles different AES modes in one run() method, chosen by algorithm.
# ------------------------------------------------------------------------

class EncryptThread(QThread):
    progress_signal = pyqtSignal(int)
    done_signal = pyqtSignal(bool, str)

    def __init__(self, input_file: str, output_file: str, key: bytes, algorithm: str, parent=None):
        """
        algorithm: "AES-256-GCM", "AES-256-CBC", or "AES-256-CTR"
        """
        super().__init__(parent)
        self.input_file = input_file
        self.output_file = output_file
        self.key = key
        self.algorithm = algorithm

    def run(self):
        try:
            if self.algorithm == "AES-256-GCM":
                self.encrypt_gcm()
            elif self.algorithm == "AES-256-CBC":
                self.encrypt_cbc()
            elif self.algorithm == "AES-256-CTR":
                self.encrypt_ctr()
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
            self.done_signal.emit(True, f"Encryption ({self.algorithm}) completed.")
        except Exception as e:
            self.done_signal.emit(False, f"Encryption failed ({self.algorithm}): {e}")

    # ---------------------------
    # AES-GCM chunk-based
    # ---------------------------
    def encrypt_gcm(self):
        file_size = os.path.getsize(self.input_file)
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        processed = 0
        with open(self.input_file, "rb") as fin, open(self.output_file, "wb") as fout:
            # Write nonce, reserve space for tag
            fout.write(nonce)
            fout.seek(12 + 16)  # skip 12 bytes for nonce + 16 for tag

            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                enc_chunk = encryptor.update(chunk)
                fout.write(enc_chunk)
                processed += len(chunk)
                progress = int(processed * 100 / file_size)
                self.progress_signal.emit(progress)

            final_chunk = encryptor.finalize()
            fout.write(final_chunk)
            tag = encryptor.tag
            # Write tag back
            fout.seek(12)
            fout.write(tag)

    # ---------------------------
    # AES-CBC with HMAC
    # ---------------------------
    def encrypt_cbc(self):
        data = self.read_entire_file()  # read entire file into memory
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        padded_data = pkcs7_pad(data, 16)
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # HMAC(iv + ciphertext)
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(iv + ciphertext)
        mac = h.finalize()

        self.progress_signal.emit(100)

        with open(self.output_file, "wb") as fout:
            # [iv(16) + ciphertext(...) + mac(32)]
            fout.write(iv)
            fout.write(ciphertext)
            fout.write(mac)

    # ---------------------------
    # AES-CTR with HMAC
    # ---------------------------
    def encrypt_ctr(self):
        data = self.read_entire_file()
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()

        # HMAC(iv + ciphertext)
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(iv + ciphertext)
        mac = h.finalize()

        self.progress_signal.emit(100)

        with open(self.output_file, "wb") as fout:
            # [iv(16) + ciphertext(...) + mac(32)]
            fout.write(iv)
            fout.write(ciphertext)
            fout.write(mac)

    def read_entire_file(self) -> bytes:
        """Convenience method to read entire input file and update progress after reading."""
        file_size = os.path.getsize(self.input_file)
        processed = 0
        data = b''
        with open(self.input_file, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                data += chunk
                processed += len(chunk)
                progress = int(processed * 100 / file_size)
                self.progress_signal.emit(progress)
        return data

class DecryptThread(QThread):
    progress_signal = pyqtSignal(int)
    done_signal = pyqtSignal(bool, str)

    def __init__(self, input_file: str, output_file: str, key: bytes, algorithm: str, parent=None):
        super().__init__(parent)
        self.input_file = input_file
        self.output_file = output_file
        self.key = key
        self.algorithm = algorithm

    def run(self):
        try:
            if self.algorithm == "AES-256-GCM":
                self.decrypt_gcm()
            elif self.algorithm == "AES-256-CBC":
                self.decrypt_cbc()
            elif self.algorithm == "AES-256-CTR":
                self.decrypt_ctr()
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
            self.done_signal.emit(True, f"Decryption ({self.algorithm}) completed.")
        except Exception as e:
            self.done_signal.emit(False, f"Decryption failed ({self.algorithm}): {e}")

    # ---------------------------
    # AES-GCM chunk-based
    # ---------------------------
    def decrypt_gcm(self):
        file_size = os.path.getsize(self.input_file)
        with open(self.input_file, "rb") as fin:
            header = fin.read(12 + 16)
            if len(header) < 28:
                raise ValueError("Invalid GCM file (nonce+tag too short).")

            nonce = header[:12]
            tag = header[12:28]
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()

            processed = 28
            with open(self.output_file, "wb") as fout:
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dec_chunk = decryptor.update(chunk)
                    fout.write(dec_chunk)
                    processed += len(chunk)
                    progress = int(processed * 100 / file_size)
                    self.progress_signal.emit(progress)

                final_chunk = decryptor.finalize()
                fout.write(final_chunk)

    # ---------------------------
    # AES-CBC with HMAC
    # ---------------------------
    def decrypt_cbc(self):
        data = self.read_entire_file()
        if len(data) < 16 + 32:
            raise ValueError("Invalid CBC file (missing IV or HMAC).")

        iv = data[:16]
        mac = data[-32:]
        ciphertext = data[16:-32]

        # Verify HMAC
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(iv + ciphertext)
        h.verify(mac)

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = pkcs7_unpad(padded_plain, 16)

        self.progress_signal.emit(100)
        with open(self.output_file, "wb") as fout:
            fout.write(plaintext)

    # ---------------------------
    # AES-CTR with HMAC
    # ---------------------------
    def decrypt_ctr(self):
        data = self.read_entire_file()
        if len(data) < 16 + 32:
            raise ValueError("Invalid CTR file (missing IV or HMAC).")

        iv = data[:16]
        mac = data[-32:]
        ciphertext = data[16:-32]

        # Verify HMAC
        h = hmac.HMAC(self.key, hashes.SHA256())
        h.update(iv + ciphertext)
        h.verify(mac)

        cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        self.progress_signal.emit(100)
        with open(self.output_file, "wb") as fout:
            fout.write(plaintext)

    def read_entire_file(self) -> bytes:
        """Convenience method to read entire input file and update progress after reading."""
        file_size = os.path.getsize(self.input_file)
        processed = 0
        data = b''
        with open(self.input_file, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                data += chunk
                processed += len(chunk)
                progress = int(processed * 100 / file_size)
                self.progress_signal.emit(progress)
        return data

# ------------------------------------------------------------------------
# MainWindow with QTabWidget:
#   - Key Management tab
#   - Encryption tab (with algorithm selection, bigger buttons)
#   - Decryption tab (with same algorithm selection, bigger buttons)
# ------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-256 Multi-Mode Encrypt/Decrypt with HMAC and Argon2")
        self.resize(900, 600)

        self.apply_custom_palette()

        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.tab_key_mgmt = QWidget()
        self.tab_encrypt = QWidget()
        self.tab_decrypt = QWidget()

        self.tab_widget.addTab(self.tab_key_mgmt, "Key Management")
        self.tab_widget.addTab(self.tab_encrypt, "Encryption")
        self.tab_widget.addTab(self.tab_decrypt, "Decryption")

        self.setup_key_mgmt_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        self.encrypt_thread = None
        self.decrypt_thread = None
        self.key_data = None

    def apply_custom_palette(self):
        QApplication.setStyle("Fusion")
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(35, 35, 35))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)

        QApplication.instance().setPalette(palette)

    # ---------------------------
    # Key Management Tab
    # ---------------------------
    def setup_key_mgmt_tab(self):
        layout = QVBoxLayout(self.tab_key_mgmt)

        group = QGroupBox("Key Management")
        group_layout = QHBoxLayout(group)
        layout.addWidget(group)

        self.label_key_info = QLabel("No key loaded")
        group_layout.addWidget(self.label_key_info)

        self.btn_gen_key = QPushButton("Generate New Key")
        self.btn_gen_key.setFixedSize(150, 40)  # bigger button
        self.btn_gen_key.clicked.connect(self.generate_key)
        group_layout.addWidget(self.btn_gen_key)

        self.btn_save_key = QPushButton("Save Key")
        self.btn_save_key.setFixedSize(120, 40)  # bigger button
        self.btn_save_key.clicked.connect(self.save_key)
        group_layout.addWidget(self.btn_save_key)

        self.btn_load_key = QPushButton("Load Key")
        self.btn_load_key.setFixedSize(120, 40)  # bigger button
        self.btn_load_key.clicked.connect(self.load_key)
        group_layout.addWidget(self.btn_load_key)

        mode_box = QGroupBox("Key Storage Mode")
        mode_layout = QHBoxLayout(mode_box)
        self.radio_standard = QRadioButton("Standard")
        self.radio_standard.setChecked(True)
        self.radio_passphrase = QRadioButton("Passphrase")
        mode_layout.addWidget(self.radio_standard)
        mode_layout.addWidget(self.radio_passphrase)
        layout.addWidget(mode_box)

        self.key_mode_group = QButtonGroup(self)
        self.key_mode_group.addButton(self.radio_standard, 0)
        self.key_mode_group.addButton(self.radio_passphrase, 1)

        layout.addStretch(1)

    def generate_key(self):
        self.key_data = KeyManager.generate_key()
        self.label_key_info.setText("A new 32-byte AES key is generated (not saved).")
        QMessageBox.information(self, "Success", "A new AES-256 key has been generated.\nPlease remember to save it.")

    def save_key(self):
        if not self.key_data:
            QMessageBox.warning(self, "Warning", "No key to save.")
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Save Key", "", "Key Files (*.key);;All Files (*)")
        if not save_path:
            return
        mode_id = self.key_mode_group.checkedId()
        mode_str = "standard" if mode_id == 0 else "passphrase"
        try:
            KeyManager.save_key(self.key_data, save_path, mode_str)
            QMessageBox.information(self, "Success", f"Key saved to: {save_path}")
            self.label_key_info.setText(f"Key File: {os.path.basename(save_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save key: {e}")

    def load_key(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Key", "", "Key Files (*.key);;All Files (*)")
        if not file_path:
            return
        mode_id = self.key_mode_group.checkedId()
        mode_str = "standard" if mode_id == 0 else "passphrase"
        try:
            loaded_key = KeyManager.load_key(file_path, mode_str)
            self.key_data = loaded_key
            QMessageBox.information(self, "Success", f"Key loaded successfully from {file_path}.")
            self.label_key_info.setText(f"Loaded Key: {os.path.basename(file_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load key: {e}")

    # ---------------------------
    # Encryption Tab
    # ---------------------------
    def setup_encrypt_tab(self):
        layout = QVBoxLayout(self.tab_encrypt)
        group = QGroupBox("Encryption")
        group_layout = QGridLayout(group)
        layout.addWidget(group)

        self.encrypt_file_edit = QLineEdit()
        self.encrypt_file_edit.setPlaceholderText("File to encrypt...")
        self.encrypt_file_edit.setFixedHeight(30)

        btn_browse_enc = QPushButton("Browse")
        btn_browse_enc.setFixedSize(100, 40)
        btn_browse_enc.clicked.connect(self.browse_encrypt_file)

        group_layout.addWidget(QLabel("Input File:"), 0, 0)
        group_layout.addWidget(self.encrypt_file_edit, 0, 1)
        group_layout.addWidget(btn_browse_enc, 0, 2)

        # Algorithm selection
        group_layout.addWidget(QLabel("Algorithm:"), 1, 0)
        self.combo_alg_enc = QComboBox()
        self.combo_alg_enc.addItems(["AES-256-GCM", "AES-256-CBC", "AES-256-CTR"])
        self.combo_alg_enc.setFixedHeight(30)
        group_layout.addWidget(self.combo_alg_enc, 1, 1)

        self.btn_encrypt = QPushButton("Start Encryption")
        self.btn_encrypt.setFixedSize(140, 40)
        self.btn_encrypt.clicked.connect(self.handle_encrypt)
        group_layout.addWidget(self.btn_encrypt, 1, 2)

        self.encrypt_progress = QProgressBar()
        self.encrypt_progress.setValue(0)
        group_layout.addWidget(self.encrypt_progress, 2, 0, 1, 3)

        layout.addStretch(1)

    def browse_encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.encrypt_file_edit.setText(file_path)

    def handle_encrypt(self):
        if not self.key_data:
            QMessageBox.warning(self, "Warning", "No key loaded or generated.")
            return
        input_file = self.encrypt_file_edit.text().strip()
        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Warning", "Please select a valid file to encrypt.")
            return

        output_file, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", input_file + ".enc", "Encrypted Files (*.enc);;All Files (*)")
        if not output_file:
            return

        # Compute SHA-256 of the original file, store .hash
        original_hash = compute_sha256(input_file)
        hash_path = output_file + ".hash"
        try:
            with open(hash_path, 'w') as hf:
                hf.write(original_hash)
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to save hash file: {e}")

        algorithm = self.combo_alg_enc.currentText()

        self.encrypt_thread = EncryptThread(input_file, output_file, self.key_data, algorithm)
        self.encrypt_thread.progress_signal.connect(self.encrypt_progress.setValue)
        self.encrypt_thread.done_signal.connect(self.on_encrypt_done)

        self.encrypt_progress.setValue(0)
        self.btn_encrypt.setEnabled(False)
        self.encrypt_thread.start()

    def on_encrypt_done(self, success, msg):
        self.btn_encrypt.setEnabled(True)
        if success:
            QMessageBox.information(self, "Done", msg)
        else:
            QMessageBox.critical(self, "Error", msg)

    # ---------------------------
    # Decryption Tab
    # ---------------------------
    def setup_decrypt_tab(self):
        layout = QVBoxLayout(self.tab_decrypt)
        group = QGroupBox("Decryption")
        group_layout = QGridLayout(group)
        layout.addWidget(group)

        self.decrypt_file_edit = QLineEdit()
        self.decrypt_file_edit.setPlaceholderText("File to decrypt...")
        self.decrypt_file_edit.setFixedHeight(30)

        btn_browse_dec = QPushButton("Browse")
        btn_browse_dec.setFixedSize(100, 40)
        btn_browse_dec.clicked.connect(self.browse_decrypt_file)

        group_layout.addWidget(QLabel("Input File:"), 0, 0)
        group_layout.addWidget(self.decrypt_file_edit, 0, 1)
        group_layout.addWidget(btn_browse_dec, 0, 2)

        group_layout.addWidget(QLabel("Algorithm:"), 1, 0)
        self.combo_alg_dec = QComboBox()
        self.combo_alg_dec.addItems(["AES-256-GCM", "AES-256-CBC", "AES-256-CTR"])
        self.combo_alg_dec.setFixedHeight(30)
        group_layout.addWidget(self.combo_alg_dec, 1, 1)

        self.btn_decrypt = QPushButton("Start Decryption")
        self.btn_decrypt.setFixedSize(140, 40)
        self.btn_decrypt.clicked.connect(self.handle_decrypt)
        group_layout.addWidget(self.btn_decrypt, 1, 2)

        self.decrypt_progress = QProgressBar()
        self.decrypt_progress.setValue(0)
        group_layout.addWidget(self.decrypt_progress, 2, 0, 1, 3)

        layout.addStretch(1)

    def browse_decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            self.decrypt_file_edit.setText(file_path)

    def handle_decrypt(self):
        if not self.key_data:
            QMessageBox.warning(self, "Warning", "No key loaded or generated.")
            return
        input_file = self.decrypt_file_edit.text().strip()
        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Warning", "Please select a valid file to decrypt.")
            return

        output_file, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", input_file + ".dec", "All Files (*)")
        if not output_file:
            return

        algorithm = self.combo_alg_dec.currentText()

        self.decrypt_thread = DecryptThread(input_file, output_file, self.key_data, algorithm)
        self.decrypt_thread.progress_signal.connect(self.decrypt_progress.setValue)
        self.decrypt_thread.done_signal.connect(self.on_decrypt_done)

        self.decrypt_progress.setValue(0)
        self.btn_decrypt.setEnabled(False)
        self.decrypt_thread.start()

    def on_decrypt_done(self, success, msg):
        self.btn_decrypt.setEnabled(True)
        if success:
            QMessageBox.information(self, "Done", msg)
        else:
            QMessageBox.critical(self, "Error", msg)

def compute_sha256(file_path):
    """Compute SHA-256 hash of an entire file."""
    sha = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()

# ------------------------------------------------------------------------
# Main Execution
# ------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
