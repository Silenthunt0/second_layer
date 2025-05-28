import os
import tkinter as tk
from tkinter import scrolledtext, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pathlib
import base64
import struct

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

def pad_message(msg: bytes, block_size: int = 1024) -> bytes:
    pad_len = block_size - (len(msg) % block_size)
    return msg + os.urandom(pad_len)

def load_keypair():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key

def encrypt_text():
    try:
        key = os.urandom(32)
        nonce = os.urandom(12)

        message = plaintext_input.get("1.0", tk.END).strip().encode()
        orig_len = len(message)
        length_prefix = struct.pack(">I", orig_len)
        padded_msg = pad_message(length_prefix + message, block_size=1024)
        aes_cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = aes_cipher.encryptor()
        ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
        tag = encryptor.tag

        version = b'\x01'

        metadata_unencrypted = version + key + nonce + tag
        other_pub_key_pem = other_pub_key_input.get("1.0", tk.END).strip()
        other_pub_key = serialization.load_pem_public_key(other_pub_key_pem.encode(), backend=default_backend())

        encrypted_key_block = other_pub_key.encrypt(
            metadata_unencrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        result = {
            "key_block": base64.b64encode(encrypted_key_block).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        output_string = f"{result['key_block']}--{result['ciphertext']}"
        encrypted_output.delete("1.0", tk.END)
        encrypted_output.insert(tk.END, output_string)

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


def decrypt_text():
    try:
        encrypted_combined = encrypted_output.get("1.0", tk.END).strip()
        if '--' not in encrypted_combined:
            raise ValueError("Invalid encrypted format. Expecting '<key_block>--<ciphertext>'")

        encrypted_key_b64, ciphertext_b64 = encrypted_combined.split('--', 1)
        encrypted_key_block = base64.b64decode(encrypted_key_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        metadata_unencrypted = private_key.decrypt(
            encrypted_key_block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if len(metadata_unencrypted) != 1 + 32 + 12 + 16:
            raise ValueError("Unexpected metadata size")

        version = metadata_unencrypted[0:1]
        key = metadata_unencrypted[1:33]
        nonce = metadata_unencrypted[33:45]
        tag = metadata_unencrypted[45:61]

        aes_cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = aes_cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        orig_len = int.from_bytes(padded_plaintext[:4], byteorder='big')
        message = padded_plaintext[4:4 + orig_len]

        plaintext_input.delete("1.0", tk.END)
        plaintext_input.insert(tk.END, message.decode())

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
