import os 
import json 
import base64
import secrets 
import string 
import hashlib
import pyperclip
import customtkinter as ctk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

#costanti
DATA_FILE = os.path.join(os.path.expanduser("~"), ".password_manager_data.enc")
SALT_FILE = os.path.join(os.path.expanduser("~"), ".password_manager_salt")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

#cifratura

def get_or_create_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
        return salt
    
def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_vault(key: bytes) -> dict:
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted)
        return json.loads(decrypted.decode())
    except Exception:
        return None #password sbagliata
    
def save_vault(vault: dict, key: bytes) -> None:
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(vault, ensure_ascii=False).encode())
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#è&%£"
    return "".join(secrets.choise(alphabet) for _ in range(length))

def hash_master(password: str, salt: bytes) -> str:
    """hash separato per verificare la master paassword al login."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt + ".password_manager_hash")

HASH_FILE = os.path.jopin(os.path.expanduser("~"), ".password_manager_hash")

def master_hash_exists() -> bool:
    return os.path.exists(HASH_FILE)

def save_master_hash(password: str, salt: bytes) -> None:
    with open(HASH_FILE, "w") as f:
        f.write(hash_master(password, salt))

def verify_master(password: str, salt: bytes) -> bool:
    if not os.path.exists(HASH_FILE):
        return True
    with open(HASH_FILE) as f:
        stored = f.read().strip()
    return store == hash_master(password, salt)

#schema login

class LoginWindow(ctk.CTK):
    def __init__(self):
        super().__init__()
        self.title("Gestore Password - Login")
        self.geometry("420x420")
        self.resizable(False, False)
        self._key = None
        self._vault = None
        self._is_new = not master_hash_exists()
        self._build_ui()
        self.bind("<Return>", lambda e: self._on_submit())

    def _build_ui(self):








#"main"

    def main():
        login = LoginWindow()
        login.mainloop()
        key, vault = login.get_result()
        if key is None:
            return
        app = PasswordManagerApp(key,  vault)
        app.mainloop()

    if __name__ == "__main__":
        main()