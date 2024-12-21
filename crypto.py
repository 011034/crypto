import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
import os
import secrets
import hashlib

CHUNK_SIZE = 1024 * 1024

def compute_sha256(file_path):
    # Compute SHA-256 hash of an entire file.
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
    # Apply PKCS#7 padding for CBC mode.
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data, block_size=16):
    # Remove PKCS#7 padding.
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding bytes.")
    if any(x != pad_len for x in data[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]

class FileEncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption/Decryption Tool (AES-256)")

        # AES key (32 bytes for AES-256)
        self.key = None
        self.key_path = ""

        # Key mode: 0 = standard key, 1 = passphrase-encrypted key
        self.key_mode = tk.IntVar(value=0)

        # Encryption algorithm/mode selection
        self.algo_var = tk.StringVar(value="AES-256-GCM")  # default to GCM

        self.create_widgets()

    def create_widgets(self):
        # Key Management Frame
        key_frame = tk.LabelFrame(self.master, text="Key Management", padx=10, pady=10)
        key_frame.pack(padx=10, pady=5, fill="both")

        self.key_label = tk.Label(key_frame, text="No key loaded")
        self.key_label.grid(row=0, column=0, columnspan=3, pady=5)

        load_key_btn = tk.Button(key_frame, text="Load Key", command=self.load_key)
        load_key_btn.grid(row=1, column=0, padx=5, pady=5)

        generate_key_btn = tk.Button(key_frame, text="Generate New Key (256-bit)", command=self.generate_key)
        generate_key_btn.grid(row=1, column=1, padx=5, pady=5)

        save_key_btn = tk.Button(key_frame, text="Save Key", command=self.save_key)
        save_key_btn.grid(row=1, column=2, padx=5, pady=5)

        # Key Mode Selection
        mode_frame = tk.Frame(self.master)
        mode_frame.pack(padx=10, pady=5, anchor='ne')

        tk.Label(mode_frame, text="Key Storage Mode:").grid(row=0, column=0, padx=5)
        tk.Radiobutton(mode_frame, text="Standard Key", variable=self.key_mode, value=0).grid(row=0, column=1, padx=5)
        tk.Radiobutton(mode_frame, text="Encrypted Key w/ Passphrase", variable=self.key_mode, value=1).grid(row=0, column=2, padx=5)

        # Algorithm/Mode Selection Frame
        algo_frame = tk.LabelFrame(self.master, text="Algorithm/Mode Selection", padx=10, pady=10)
        algo_frame.pack(padx=10, pady=5, fill="both")

        tk.Label(algo_frame, text="Select AES Mode:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.algo_combo = ttk.Combobox(
            algo_frame,
            textvariable=self.algo_var,
            values=["AES-256-GCM", "AES-256-CBC", "AES-256-CTR"],
            state="readonly"
        )
        self.algo_combo.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        self.algo_combo.current(0)

        # Encryption Frame
        encrypt_frame = tk.LabelFrame(self.master, text="Encrypt File", padx=10, pady=10)
        encrypt_frame.pack(padx=10, pady=5, fill="both")

        self.encrypt_path = tk.StringVar()
        tk.Label(encrypt_frame, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(encrypt_frame, textvariable=self.encrypt_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(encrypt_frame, text="Browse", command=self.browse_encrypt_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_file).grid(row=1, column=0, columnspan=3, pady=10)

        # Decryption Frame
        decrypt_frame = tk.LabelFrame(self.master, text="Decrypt File", padx=10, pady=10)
        decrypt_frame.pack(padx=10, pady=5, fill="both")

        self.decrypt_path = tk.StringVar()
        tk.Label(decrypt_frame, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(decrypt_frame, textvariable=self.decrypt_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(decrypt_frame, text="Browse", command=self.browse_decrypt_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_file).grid(row=1, column=0, columnspan=3, pady=10)

    # ---------------------------
    # Key Management Methods
    # ---------------------------

    def load_key(self):
        key_file = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if key_file:
            try:
                with open(key_file, 'rb') as f:
                    key_data = f.read()

                if self.key_mode.get() == 0:
                    # Standard Key mode
                    if len(key_data) != 32:
                        messagebox.showerror("Error", "Invalid key file for Standard Mode. Must be 32 bytes.")
                        return
                    self.key = key_data
                else:
                    # Passphrase-encrypted key
                    if len(key_data) < (12 + 16 + 32 + 16):
                        messagebox.showerror("Error", "Invalid key file (too small) for Encrypted Mode.")
                        return

                    nonce = key_data[:12]
                    tag = key_data[12:28]
                    enc_key = key_data[28:-16]
                    salt = key_data[-16:]

                    passphrase = simpledialog.askstring("Passphrase Required", "Enter passphrase to unlock key:", show='*')
                    if passphrase is None:
                        return

                    kek = self.derive_kek(passphrase, salt)
                    cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    self.key = decryptor.update(enc_key) + decryptor.finalize()

                    if len(self.key) != 32:
                        messagebox.showerror("Error", "Decrypted key is not 32 bytes. Possibly wrong passphrase or invalid file.")
                        self.key = None
                        return

                self.key_path = key_file
                self.key_label.config(text=f"Key File: {os.path.basename(key_file)}")
                messagebox.showinfo("Success", "Key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def generate_key(self):
        self.key = secrets.token_bytes(32)
        self.key_label.config(text="A new key has been generated. Please save it.")
        messagebox.showinfo("Success", "A new 256-bit key has been generated. Please remember to save it.")

    def save_key(self):
        if self.key is None:
            messagebox.showwarning("Warning", "No key to save.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Key",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if not save_path:
            return

        try:
            if self.key_mode.get() == 0:
                # Standard mode (raw key)
                with open(save_path, 'wb') as f:
                    f.write(self.key)
            else:
                # Passphrase-encrypted key mode
                passphrase = simpledialog.askstring("Passphrase", "Enter passphrase to encrypt the key:", show='*')
                if passphrase is None or passphrase.strip() == "":
                    messagebox.showwarning("Warning", "No passphrase provided. Key not saved.")
                    return

                if not check_password_strength(passphrase):
                    messagebox.showwarning("Warning", "Your passphrase is too weak. Please add more complexity.")
                    return

                salt = secrets.token_bytes(16)
                kek = self.derive_kek(passphrase, salt)
                nonce = secrets.token_bytes(12)

                cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                enc_key = encryptor.update(self.key) + encryptor.finalize()
                tag = encryptor.tag

                with open(save_path, 'wb') as f:
                    f.write(nonce)
                    f.write(tag)
                    f.write(enc_key)
                    f.write(salt)

            self.key_path = save_path
            self.key_label.config(text=f"Key File: {os.path.basename(save_path)}")
            messagebox.showinfo("Success", "Key saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save key: {e}")

    # ---------------------------
    # Encryption/Decryption
    # ---------------------------

    def browse_encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            self.encrypt_path.set(file_path)

    def browse_decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if file_path:
            self.decrypt_path.set(file_path)

    def encrypt_file(self):
        """
        Reads the entire file, optionally pads (CBC), uses GCM/CTR/HMAC for authentication,
        and writes a single encrypted output. Also saves a .hash file for optional integrity check.
        """
        if self.key is None:
            messagebox.showwarning("Warning", "Please load or generate a key first.")
            return

        input_path = self.encrypt_path.get()
        if not input_path:
            messagebox.showwarning("Warning", "Please select a file to encrypt.")
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not output_path:
            return

        algo_mode = self.algo_var.get()

        # Compute SHA-256 of the original file, store .hash
        original_hash = compute_sha256(input_path)
        hash_path = output_path + ".hash"
        try:
            with open(hash_path, 'w') as hf:
                hf.write(original_hash)
        except Exception as e:
            messagebox.showwarning("Warning", f"Failed to save hash file: {e}")

        try:
            # Read entire plaintext
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
                # PKCS#7 pad
                padded_data = pkcs7_pad(plaintext_data, 16)
                iv = secrets.token_bytes(16)
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                # HMAC(iv + ciphertext)
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                mac = h.finalize()

                # Format: [iv(16)] + [ciphertext...] + [mac(32)]
                with open(output_path, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ciphertext)
                    fout.write(mac)

            elif algo_mode == "AES-256-CTR":
                iv = secrets.token_bytes(16)  # used as nonce/initial counter
                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(plaintext_data) + encryptor.finalize()

                # HMAC(iv + ciphertext)
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                mac = h.finalize()

                # Format: [iv(16)] + [ciphertext...] + [mac(32)]
                with open(output_path, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ciphertext)
                    fout.write(mac)

            else:
                raise ValueError(f"Unsupported mode: {algo_mode}")

            messagebox.showinfo("Success", f"File encrypted with {algo_mode} and saved to:\n{output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed ({algo_mode}): {e}")

    def decrypt_file(self):
        """
        Reads the entire encrypted file, extracts IV/nonce/tag/HMAC, verifies integrity,
        removes PKCS#7 padding (if CBC), then outputs the original plaintext.
        """
        if self.key is None:
            messagebox.showwarning("Warning", "Please load or generate a key first.")
            return

        input_path = self.decrypt_path.get()
        if not input_path:
            messagebox.showwarning("Warning", "Please select a file to decrypt.")
            return

        output_path = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            defaultextension="",
            filetypes=[("All Files", "*.*")]
        )
        if not output_path:
            return

        algo_mode = self.algo_var.get()

        try:
            enc_data = open(input_path, 'rb').read()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open input file: {e}")
            return

        try:
            if algo_mode == "AES-256-GCM":
                # Format: [nonce(12)] + [tag(16)] + [ciphertext...]
                if len(enc_data) < 28:
                    raise ValueError("Invalid GCM file (too short).")
                nonce = enc_data[:12]
                tag = enc_data[12:28]
                ciphertext = enc_data[28:]

                cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            elif algo_mode == "AES-256-CBC":
                # Format: [iv(16)] + [ciphertext...] + [mac(32)]
                if len(enc_data) < 16 + 32:
                    raise ValueError("Invalid CBC file (too short).")
                iv = enc_data[:16]
                mac = enc_data[-32:]
                ciphertext = enc_data[16:-32]

                # HMAC check
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                h.verify(mac)

                cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
                plaintext = pkcs7_unpad(padded_plain, 16)

            elif algo_mode == "AES-256-CTR":
                # Format: [iv(16)] + [ciphertext...] + [mac(32)]
                if len(enc_data) < 16 + 32:
                    raise ValueError("Invalid CTR file (too short).")
                iv = enc_data[:16]
                mac = enc_data[-32:]
                ciphertext = enc_data[16:-32]

                # HMAC check
                h = hmac.HMAC(self.key, hashes.SHA256())
                h.update(iv + ciphertext)
                h.verify(mac)

                cipher = Cipher(algorithms.AES(self.key), modes.CTR(iv))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            else:
                raise ValueError(f"Unsupported mode: {algo_mode}")

            # Write plaintext to output
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted with {algo_mode} and saved to:\n{output_path}")

            # Check optional .hash file
            hash_path = input_path + ".hash"
            if os.path.exists(hash_path):
                with open(hash_path, 'r') as hf:
                    saved_hash = hf.read().strip()
                new_hash = compute_sha256(output_path)
                if saved_hash == new_hash:
                    messagebox.showinfo("Integrity Check", "Decrypted file matches the original hash.")
                else:
                    messagebox.showwarning("Warning", "Decrypted file hash does NOT match. Possible corruption.")
            else:
                messagebox.showinfo("Info", "No .hash file found. Skipping hash check.")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed ({algo_mode}): {e}")

    def derive_kek(self, passphrase, salt):
        """Derive the Key Encryption Key (KEK) from the user's passphrase using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(passphrase.encode('utf-8'))

def main():
    root = tk.Tk()
    app = FileEncryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
