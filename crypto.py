import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import secrets
import base64

class FileEncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption/Decryption Tool (AES-256-GCM)")

        self.key = None
        self.key_path = ""

        self.key_mode = tk.IntVar(value=0)

        self.create_widgets()

    def create_widgets(self):
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

        mode_frame = tk.Frame(self.master)
        mode_frame.pack(padx=10, pady=5, anchor='ne')

        tk.Label(mode_frame, text="Key Storage Mode:").pack(side='left', padx=5)
        tk.Radiobutton(mode_frame, text="Standard Key", variable=self.key_mode, value=0).pack(side='left', padx=5)
        tk.Radiobutton(mode_frame, text="Encrypted Key with Passphrase", variable=self.key_mode, value=1).pack(side='left', padx=5)

        encrypt_frame = tk.LabelFrame(self.master, text="Encrypt File", padx=10, pady=10)
        encrypt_frame.pack(padx=10, pady=5, fill="both")

        self.encrypt_path = tk.StringVar()
        tk.Label(encrypt_frame, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(encrypt_frame, textvariable=self.encrypt_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(encrypt_frame, text="Browse", command=self.browse_encrypt_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_file).grid(row=1, column=0, columnspan=3, pady=10)

        decrypt_frame = tk.LabelFrame(self.master, text="Decrypt File", padx=10, pady=10)
        decrypt_frame.pack(padx=10, pady=5, fill="both")

        self.decrypt_path = tk.StringVar()
        tk.Label(decrypt_frame, text="Select File:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(decrypt_frame, textvariable=self.decrypt_path, width=50).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(decrypt_frame, text="Browse", command=self.browse_decrypt_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_file).grid(row=1, column=0, columnspan=3, pady=10)

    def load_key(self):
        key_file = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if key_file:
            try:
                with open(key_file, 'rb') as f:
                    key_data = f.read()

                if self.key_mode.get() == 0:
                    if len(key_data) != 32:
                        messagebox.showerror("Error", "Invalid key file for Standard Mode. Must be 32 bytes.")
                        return
                    self.key = key_data
                else:
                    if len(key_data) < 60:
                        messagebox.showerror("Error", "Invalid key file for Encrypted Mode.")
                        return
                    nonce = key_data[:12]
                    tag = key_data[12:28]
                    enc_key = key_data[28:]

                    passphrase = simpledialog.askstring("Passphrase Required", "Enter passphrase to unlock key:", show='*')
                    if passphrase is None:
                        return

                    kek = self.derive_kek(passphrase)
                    cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce, tag))
                    decryptor = cipher.decryptor()
                    self.key = decryptor.update(enc_key) + decryptor.finalize()

                    if len(self.key) != 32:
                        messagebox.showerror("Error", "Decrypted key is not 32 bytes. Invalid file or passphrase?")
                        self.key = None
                        return

                self.key_path = key_file
                self.key_label.config(text=f"Key File: {os.path.basename(key_file)}")
                messagebox.showinfo("Success", "Key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def generate_key(self):
        self.key = secrets.token_bytes(32)
        self.key_label.config(text="A new key has been generated. Please save the key.")
        messagebox.showinfo("Success", "A new 256-bit key has been generated. Please remember to save it.")

    def save_key(self):
        if self.key is None:
            messagebox.showwarning("Warning", "No key to save.")
            return
        save_path = filedialog.asksaveasfilename(title="Save Key", defaultextension=".key", filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if save_path:
            try:
                if self.key_mode.get() == 0:
                    with open(save_path, 'wb') as f:
                        f.write(self.key)
                else:
                    passphrase = simpledialog.askstring("Passphrase", "Enter a passphrase to encrypt the key:", show='*')
                    if passphrase is None or passphrase.strip() == "":
                        messagebox.showwarning("Warning", "No passphrase provided. Key not saved.")
                        return

                    kek = self.derive_kek(passphrase)
                    nonce = secrets.token_bytes(12)
                    cipher = Cipher(algorithms.AES(kek), modes.GCM(nonce))
                    encryptor = cipher.encryptor()
                    enc_key = encryptor.update(self.key) + encryptor.finalize()
                    tag = encryptor.tag

                    with open(save_path, 'wb') as f:
                        f.write(nonce)
                        f.write(tag)
                        f.write(enc_key)

                self.key_path = save_path
                self.key_label.config(text=f"Key File: {os.path.basename(save_path)}")
                messagebox.showinfo("Success", "Key saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {e}")

    def browse_encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            self.encrypt_path.set(file_path)

    def browse_decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if file_path:
            self.decrypt_path.set(file_path)

    def encrypt_file(self):
        if self.key is None:
            messagebox.showwarning("Warning", "Please load or generate a key first.")
            return
        input_path = self.encrypt_path.get()
        if not input_path:
            messagebox.showwarning("Warning", "Please select a file to encrypt.")
            return
        output_path = filedialog.asksaveasfilename(title="Save Encrypted File", defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
        if not output_path:
            return
        try:
            with open(input_path, 'rb') as f:
                data = f.read()

            nonce = secrets.token_bytes(12)
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(data) + encryptor.finalize()

            tag = encryptor.tag

            with open(output_path, 'wb') as f:
                f.write(nonce)
                f.write(tag)
                f.write(encrypted)

            messagebox.showinfo("Success", f"File encrypted and saved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt_file(self):
        if self.key is None:
            messagebox.showwarning("Warning", "Please load or generate a key first.")
            return
        input_path = self.decrypt_path.get()
        if not input_path:
            messagebox.showwarning("Warning", "Please select a file to decrypt.")
            return
        output_path = filedialog.asksaveasfilename(title="Save Decrypted File", defaultextension="", filetypes=[("All Files", "*.*")])
        if not output_path:
            return
        try:
            with open(input_path, 'rb') as f:
                file_data = f.read()

            nonce = file_data[:12]
            tag = file_data[12:28]
            encrypted = file_data[28:]

            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted) + decryptor.finalize()

            with open(output_path, 'wb') as f:
                f.write(decrypted)

            messagebox.showinfo("Success", f"File decrypted and saved to:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def derive_kek(self, passphrase):
        salt = b'static_salt_for_demo'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        kek = kdf.derive(passphrase.encode('utf-8'))
        return kek

def main():
    root = tk.Tk()
    app = FileEncryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
