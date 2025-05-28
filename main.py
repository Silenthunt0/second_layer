import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import pathlib

APP_DIR = pathlib.Path(os.path.expanduser("~/Library/Application Support/SecondLayer"))
APP_DIR.mkdir(parents=True, exist_ok=True)

PRIVATE_KEY_FILE = APP_DIR / "private_key.pem"
PUBLIC_KEY_FILE = APP_DIR / "public_key.pem"

def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_keypair():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

def encrypt_text():
    try:
        other_pub_key_pem = other_pub_key_input.get("1.0", tk.END).strip()
        message = plaintext_input.get("1.0", tk.END).strip().encode()

        other_pub_key = serialization.load_pem_public_key(other_pub_key_pem.encode(), backend=default_backend())
        encrypted = other_pub_key.encrypt(
            message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted_output.delete("1.0", tk.END)
        encrypted_output.insert(tk.END, encrypted.hex())
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_text():
    try:
        encrypted_hex = encrypted_output.get("1.0", tk.END).strip()
        ciphertext = bytes.fromhex(encrypted_hex)
        decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        plaintext_input.delete("1.0", tk.END)
        plaintext_input.insert(tk.END, decrypted.decode())
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def copy_encrypted_text():
    encrypted_hex = encrypted_output.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(encrypted_hex)

def paste_encrypted_text():
    encrypted_hex = root.clipboard_get()
    encrypted_output.delete("1.0", tk.END)
    encrypted_output.insert(tk.END, encrypted_hex)

if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
    generate_keypair()

private_key, public_key = load_keypair()
pub_pem_str = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

root = tk.Tk()
root.title("Second Layer")

tk.Label(root, text="Your Public Key").pack()
pub_key_display = scrolledtext.ScrolledText(root, height=5, width=80)
pub_key_display.insert(tk.END, pub_pem_str)
pub_key_display.configure(state='disabled')
pub_key_display.pack()

tk.Label(root, text="Third-party Public Key").pack()
other_pub_key_input = scrolledtext.ScrolledText(root, height=5, width=80)
other_pub_key_input.pack()

tk.Label(root, text="Plaintext").pack()
plaintext_input = scrolledtext.ScrolledText(root, height=5, width=80)
plaintext_input.pack()


tk.Label(root, text="Encrypted Text (Hex)").pack()
encrypted_output = scrolledtext.ScrolledText(root, height=5, width=80)
encrypted_output.pack()
tk.Button(root, text="Copy encrypted", command=copy_encrypted_text).pack(side=tk.LEFT, padx=10, pady=10)
tk.Button(root, text="Paste encrypted", command=paste_encrypted_text).pack(side=tk.LEFT, padx=10, pady=10)

frame = tk.Frame(root)
frame.pack()

tk.Button(frame, text="Encrypt", command=encrypt_text).pack(side=tk.LEFT, padx=10, pady=10)
tk.Button(frame, text="Decrypt", command=decrypt_text).pack(side=tk.LEFT, padx=10, pady=10)

root.mainloop()
