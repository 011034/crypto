import sys
import os
import secrets
import hashlib

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QPushButton, QFileDialog, QLineEdit, QMessageBox, QInputDialog, QComboBox, QRadioButton, QButtonGroup
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac

CHUNK_SIZE = 1024 * 1024  # 1 MB per chunk

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

def check_password_strength(passphrase):
    """
    Simple password strength check:
    - At least length 8
    - Contains at least one digit
    - Contains at least one alphabet
    """
    if len(passphrase) < 8:
        return False
    has_digit = any(ch.isdigit() for ch in passphrase)
    has_alpha = any(ch.isalpha() for ch in passphrase)
    return has_digit and has_alpha

def pkcs7_pad(data, block_size=16):
    """Apply PKCS#7 padding for CBC mode."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data, block_size=16):
    """Remove PKCS#7 padding."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding bytes.")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryption/Decryption Tool (AES-256)")
        self.resize(800, 500)

        # AES key (32 bytes for AES-256)
        self.key = None
        self.key_path = ""

        # Key mode: 0 = standard key, 1 = passphrase-encrypted key
        self.key_mode = 0

        # Encryption algorithm/mode selection
        self.algo_mode = "AES-256-GCM"

        # Main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1) Key Management
        key_group = QGroupBox("Key Management")
        key_layout = QGridLayout(key_group)
        main_layout.addWidget(key_group)

        self.key_label = QLabel("No key loaded")
        key_layout.addWidget(self.key_label, 0, 0, 1, 3)

        self.btn_load_key = QPushButton("Load Key")
        self.btn_load_key.setFixedSize(120, 40)
        self.btn_load_key.clicked.connect(self.load_key)
        key_layout.addWidget(self.btn_load_key, 1, 0)

        self.btn_generate_key = QPushButton("Generate New Key (256-bit)")
        self.btn_generate_key.setFixedSize(200, 40)
        self.btn_generate_key.clicked.connect(self.generate_key)
        key_layout.addWidget(self.btn_generate_key, 1, 1)

        self.btn_save_key = QPushButton("Save Key")
        self.btn_save_key.setFixedSize(120, 40)
        self.btn_save_key.clicked.connect(self.save_key)
        key_layout.addWidget(self.btn_save_key, 1, 2)

        # 2) Key Mode Selection
        mode_box = QGroupBox("Key Storage Mode")
        mode_layout = QHBoxLayout(mode_box)
        main_layout.addWidget(mode_box)

        self.radio_standard = QRadioButton("Standard Key")
        self.radio_standard.setChecked(True)
        self.radio_standard.toggled.connect(self.on_key_mode_changed)

        self.radio_passphrase = QRadioButton("Encrypted Key w/ Passphrase")
        mode_layout.addWidget(self.radio_standard)
        mode_layout.addWidget(self.radio_passphrase)

        self.key_mode_group = QButtonGroup(self)
        self.key_mode_group.addButton(self.radio_standard, 0)
        self.key_mode_group.addButton(self.radio_passphrase, 1)

        # 3) Algorithm/Mode Selection
        algo_box = QGroupBox("Algorithm/Mode Selection")
        algo_layout = QHBoxLayout(algo_box)
        main_layout.addWidget(algo_box)

        lbl_algo = QLabel("Select AES Mode:")
        algo_layout.addWidget(lbl_algo)

        self.combo_algo = QComboBox()
        self.combo_algo.addItems(["AES-256-GCM", "AES-256-CBC", "AES-256-CTR"])
        self.combo_algo.setFixedSize(150, 30)
        self.combo_algo.currentIndexChanged.connect(self.on_algo_changed)
        algo_layout.addWidget(self.combo_algo)

        # 4) Encryption
        enc_box = QGroupBox("Encrypt File")
        enc_layout = QGridLayout(enc_box)
        main_layout.addWidget(enc_box)

        lbl_enc_file = QLabel("Select File:")
        enc_layout.addWidget(lbl_enc_file, 0, 0)

        self.encrypt_path_edit = QLineEdit()
        self.encrypt_path_edit.setFixedSize(350, 30)
        enc_layout.addWidget(self.encrypt_path_edit, 0, 1)

        self.btn_browse_enc = QPushButton("Browse")
        self.btn_browse_enc.setFixedSize(100, 35)
        self.btn_browse_enc.clicked.connect(self.browse_encrypt_file)
        enc_layout.addWidget(self.btn_browse_enc, 0, 2)

        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setFixedSize(120, 40)
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        enc_layout.addWidget(self.btn_encrypt, 1, 0, 1, 3)

        # 5) Decryption
        dec_box = QGroupBox("Decrypt File")
        dec_layout = QGridLayout(dec_box)
        main_layout.addWidget(dec_box)

        lbl_dec_file = QLabel("Select File:")
        dec_layout.addWidget(lbl_dec_file, 0, 0)

        self.decrypt_path_edit = QLineEdit()
        self.decrypt_path_edit.setFixedSize(350, 30)
        dec_layout.addWidget(self.decrypt_path_edit, 0, 1)

        self.btn_browse_dec = QPushButton("Browse")
        self.btn_browse_dec.setFixedSize(100, 35)
        self.btn_browse_dec.clicked.connect(self.browse_decrypt_file)
        dec_layout.addWidget(self.btn_browse_dec, 0, 2)

        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setFixedSize(120, 40)
        self.btn_decrypt.clicked.connect(self.decrypt_file)
        dec_layout.addWidget(self.btn_decrypt, 1, 0, 1, 3)

        main_layout.addStretch()

    # ---------------------------
    # Key Management
    # ---------------------------
    def on_key_mode_changed(self):
        """Updates self.key_mode when radio buttons are toggled."""
        if self.radio_standard.isChecked():
            self.key_mode = 0
        else:
            self.key_mode = 1

    def load_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", "", "Key Files (*.key);;All Files (*)"
        )
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                key_data = f.read()

            if self.key_mode == 0:
                # Standard Key mode
                if len(key_data) != 32:
                    QMessageBox.critical(self, "Error", "Invalid key file for Standard Mode. Must be 32 bytes.")
                    return
                self.key = key_data
            else:
                # Passphrase-encrypted key
                if len(key_data) < (12 + 16 + 32 + 16):
                    QMessageBox.critical(self, "Error", "Invalid key file (too small) for Encrypted Mode.")
                    return

                nonce = key_data[:12]
                tag = key_data[12:28]
                enc_key = key_data[28:-16]
                salt = key_data[-16:]

                passphrase, ok = QInputDialog.getText(self, "Passphrase Required", "Enter passphrase to unlock key:", echo=QLineEdit.Password)
                if not ok or not passphrase:
                    return

                kek = self.derive_kek(passphrase, salt)
                cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                self.key = decryptor.update(enc_key) + decryptor.finalize()

                if len(self.key) != 32:
                    QMessageBox.critical(self, "Error", "Decrypted key is not 32 bytes. Possibly wrong passphrase or invalid file.")
                    self.key = None
                    return

            self.key_path = file_path
            self.key_label.setText(f"Key File: {os.path.basename(file_path)}")
            QMessageBox.information(self, "Success", "Key loaded successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load key: {e}")

    def generate_key(self):
        self.key = secrets.token_bytes(32)
        self.key_label.setText("A new key has been generated. Please save it.")
        QMessageBox.information(self, "Success", "A new 256-bit key has been generated. Please remember to save it.")

    def save_key(self):
        if self.key is None:
            QMessageBox.warning(self, "Warning", "No key to save.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Key", "", "Key Files (*.key);;All Files (*)"
        )
        if not file_path:
            return
        try:
            if self.key_mode == 0:
                # Standard mode (raw key)
                with open(file_path, 'wb') as f:
                    f.write(self.key)
            else:
                # Passphrase-encrypted key mode
                passphrase, ok = QInputDialog.getText(self, "Passphrase", "Enter passphrase to encrypt the key:", echo=QLineEdit.Password)
                if not ok or not passphrase:
                    QMessageBox.warning(self, "Warning", "No passphrase provided. Key not saved.")
                    return

                if not check_password_strength(passphrase):
                    QMessageBox.warning(self, "Warning", "Your passphrase is too weak. Please add more complexity.")
                    return

                salt = secrets.token_bytes(16)
                kek = self.derive_kek(passphrase, salt)
                nonce = secrets.token_bytes(12)
                cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                enc_key = encryptor.update(self.key) + encryptor.finalize()
                tag = encryptor.tag

                with open(file_path, 'wb') as f:
                    f.write(nonce)
                    f.write(tag)
                    f.write(enc_key)
                    f.write(salt)

            self.key_path = file_path
            self.key_label.setText(f"Key File: {os.path.basename(file_path)}")
            QMessageBox.information(self, "Success", "Key saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save key: {e}")

    # ---------------------------
    # Algorithm/Mode
    # ---------------------------
    def on_algo_changed(self):
        self.algo_mode = self.combo_algo.currentText()

    # ---------------------------
    # Encryption
    # ---------------------------
    def browse_encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.encrypt_path_edit.setText(file_path)

    def encrypt_file(self):
        if self.key is None:
            QMessageBox.warning(self, "Warning", "Please load or generate a key first.")
            return
        input_path = self.encrypt_path_edit.text().strip()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self, "Warning", "Please select a valid file to encrypt.")
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Encrypted File", input_path + ".enc", "Encrypted Files (*.enc);;All Files (*)"
        )
        if not output_path:
            return

        # Save .hash file
        original_hash = compute_sha256(input_path)
        hash_path = output_path + ".hash"
        try:
            with open(hash_path, 'w') as hf:
                hf.write(original_hash)
        except Exception as e:
            QMessageBox.warning(self, "Warning", f"Failed to save hash file: {e}")

        algo_mode = self.algo_mode
        try:
            with open(input_path, 'rb') as fin:
                plaintext_data = fin.read()

            if algo_mode == "AES-256-GCM":
                nonce = secrets.token_bytes(12)
                cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext_data) + encryptor.finalize()
                tag = encryptor.tag

                # Format: [nonce(12)] + [tag(16)] + [ciphertext...]
                with open(output_path, 'wb') as fout:
                    fout.write(nonce)
                    fout.write(tag)
                    fout.write(ciphertext)

            elif algo_mode == "AES-256-CBC":
                padded_data = pkcs7_pad(plaintext_data, 16)
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                # HMAC(iv + ciphertext)
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                mac = h.finalize()

                # [iv(16)] + [ciphertext...] + [mac(32)]
                with open(output_path, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ciphertext)
                    fout.write(mac)

            elif algo_mode == "AES-256-CTR":
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext_data) + encryptor.finalize()

                # HMAC(iv + ciphertext)
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                mac = h.finalize()

                # [iv(16)] + [ciphertext...] + [mac(32)]
                with open(output_path, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ciphertext)
                    fout.write(mac)

            else:
                raise ValueError(f"Unsupported mode: {algo_mode}")

            QMessageBox.information(self, "Success", f"File encrypted with {algo_mode} and saved to:\n{output_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed ({algo_mode}): {e}")

    # ---------------------------
    # Decryption
    # ---------------------------
    def browse_decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            self.decrypt_path_edit.setText(file_path)

    def decrypt_file(self):
        if self.key is None:
            QMessageBox.warning(self, "Warning", "Please load or generate a key first.")
            return
        input_path = self.decrypt_path_edit.text().strip()
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self, "Warning", "Please select a valid file to decrypt.")
            return

        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Decrypted File", input_path + ".dec", "All Files (*)"
        )
        if not output_path:
            return

        algo_mode = self.algo_mode
        try:
            enc_data = open(input_path, 'rb').read()

            if algo_mode == "AES-256-GCM":
                # [nonce(12)] + [tag(16)] + [ciphertext...]
                if len(enc_data) < 28:
                    raise ValueError("Invalid GCM file (too short).")
                nonce = enc_data[:12]
                tag = enc_data[12:28]
                ciphertext = enc_data[28:]

                cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            elif algo_mode == "AES-256-CBC":
                # [iv(16)] + [ciphertext...] + [mac(32)]
                if len(enc_data) < 16 + 32:
                    raise ValueError("Invalid CBC file (too short).")
                iv = enc_data[:16]
                mac = enc_data[-32:]
                ciphertext = enc_data[16:-32]

                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                h.verify(mac)

                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
                plaintext = pkcs7_unpad(padded_plain, 16)

            elif algo_mode == "AES-256-CTR":
                # [iv(16)] + [ciphertext...] + [mac(32)]
                if len(enc_data) < 16 + 32:
                    raise ValueError("Invalid CTR file (too short).")
                iv = enc_data[:16]
                mac = enc_data[-32:]
                ciphertext = enc_data[16:-32]

                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                h.verify(mac)

                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            else:
                raise ValueError(f"Unsupported mode: {algo_mode}")

            with open(output_path, 'wb') as fout:
                fout.write(plaintext)

            QMessageBox.information(self, "Success", f"File decrypted with {algo_mode} and saved to:\n{output_path}")

            # Optional .hash check
            hash_path = input_path + ".hash"
            if os.path.exists(hash_path):
                with open(hash_path, 'r') as hf:
                    saved_hash = hf.read().strip()
                new_hash = compute_sha256(output_path)
                if saved_hash == new_hash:
                    QMessageBox.information(self, "Integrity Check", "Decrypted file matches the original hash.")
                else:
                    QMessageBox.warning(self, "Warning", "Decrypted file hash does NOT match. Possible corruption.")
            else:
                QMessageBox.information(self, "Info", "No .hash file found. Skipping hash check.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed ({algo_mode}): {e}")

    # ---------------------------
    # Helper for passphrase-based key
    # ---------------------------
    def derive_kek(self, passphrase, salt):
        """Derive a 32-byte KEK from passphrase + salt via PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(passphrase.encode('utf-8'))

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
