"""
password manager
dipendenze: pip install customtkinter cryptography pyperclip
"""

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

# costanti
DATA_FILE = os.path.join(os.path.expanduser("~"), ".password_manager_data.enc")
SALT_FILE = os.path.join(os.path.expanduser("~"), ".password_manager_salt")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# cifratura
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
        return None

def save_vault(vault: dict, key: bytes) -> None:
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(vault, ensure_ascii=False).encode())
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)

def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$&%*"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def hash_master(password: str, salt: bytes) -> str:
    """hash separato per verificare la master password al login."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt + b"verify",
        200_000
    ).hex()

HASH_FILE = os.path.join(os.path.expanduser("~"), ".password_manager_hash")

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
    return stored == hash_master(password, salt)


# schermata login
class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("gestore password - login")
        self.geometry("420x340")
        self.resizable(False, False)
        self._key = None
        self._vault = None
        self._is_new = not master_hash_exists()
        self._build_ui()
        self.bind("<Return>", lambda e: self._on_submit())

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self, text="gestore password",
                     font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, pady=(32, 4))

        subtitle = "crea una password master" if self._is_new else "inserisci la password master"
        ctk.CTkLabel(self, text=subtitle, font=ctk.CTkFont(size=13),
                     text_color="gray").grid(row=1, column=0, pady=(0, 20))

        self._pwd_entry = ctk.CTkEntry(self, placeholder_text="password master",
                                       show="*", width=280, height=42,
                                       font=ctk.CTkFont(size=14))
        self._pwd_entry.grid(row=2, column=0, pady=6)
        self._pwd_entry.focus()

        if self._is_new:
            self._pwd_confirm = ctk.CTkEntry(self, placeholder_text="conferma password",
                                             show="*", width=280, height=42,
                                             font=ctk.CTkFont(size=14))
            self._pwd_confirm.grid(row=3, column=0, pady=6)

        btn_text = "crea vault" if self._is_new else "accedi"
        ctk.CTkButton(self, text=btn_text, width=280, height=42,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=self._on_submit).grid(row=4, column=0, pady=20)

        self._status = ctk.CTkLabel(self, text="", text_color="#e74c3c",
                                    font=ctk.CTkFont(size=12))
        self._status.grid(row=5, column=0)

    def _on_submit(self):
        pwd = self._pwd_entry.get().strip()
        if not pwd:
            self._status.configure(text="inserisci una password.")
            return

        if self._is_new:
            confirm = self._pwd_confirm.get().strip()
            if pwd != confirm:
                self._status.configure(text="le password non coincidono.")
                return
            if len(pwd) < 8:
                self._status.configure(text="almeno 8 caratteri.")
                return
            salt = get_or_create_salt()
            save_master_hash(pwd, salt)
            self._key = derive_key(pwd, salt)
            self._vault = {}
            save_vault(self._vault, self._key)
        else:
            salt = get_or_create_salt()
            if not verify_master(pwd, salt):
                self._status.configure(text="password errata.")
                return
            self._key = derive_key(pwd, salt)
            self._vault = load_vault(self._key)
            if self._vault is None:
                self._status.configure(text="errore di decifratura.")
                return

        self.destroy()

    def get_result(self):
        return self._key, self._vault


# finestra principale
class PasswordManagerApp(ctk.CTk):
    def __init__(self, key: bytes, vault: dict):
        super().__init__()
        self._key = key
        self._vault = vault
        self._visible_passwords = {}

        self.title("gestore password")
        self.geometry("860x600")
        self.minsize(700, 480)
        self._build_ui()
        self._refresh_list()

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # barra laterale
        sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(sidebar, text="🔐", font=ctk.CTkFont(size=32)).grid(row=0, column=0, pady=(24, 4))
        ctk.CTkLabel(sidebar, text="vault", font=ctk.CTkFont(size=18, weight="bold")).grid(row=1, column=0, pady=(0, 20))

        ctk.CTkButton(sidebar, text="aggiungi", width=160,
                      command=self._open_add_dialog).grid(row=2, column=0, pady=6, padx=16)
        ctk.CTkButton(sidebar, text="genera password", width=160,
                      command=self._open_generator).grid(row=3, column=0, pady=6, padx=16)
        ctk.CTkButton(sidebar, text="cambia master", width=160,
                      command=self._change_master).grid(row=4, column=0, pady=6, padx=16)
        ctk.CTkButton(sidebar, text="esci", width=160, fg_color="transparent",
                      border_color="gray", border_width=1,
                      command=self.destroy).grid(row=5, column=0, pady=6, padx=16)

        count_text = f"{len(self._vault)} voce/i"
        self._count_label = ctk.CTkLabel(sidebar, text=count_text,
                                         text_color="gray", font=ctk.CTkFont(size=11))
        self._count_label.grid(row=7, column=0, pady=(0, 16))

        # area principale
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=16, pady=16)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        # barra di ricerca
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._refresh_list())
        search = ctk.CTkEntry(main, textvariable=self._search_var,
                              placeholder_text="cerca per sito o utente...",
                              height=38, font=ctk.CTkFont(size=13))
        search.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        # lista scrollabile
        self._list_frame = ctk.CTkScrollableFrame(main, label_text="")
        self._list_frame.grid(row=1, column=0, sticky="nsew")
        self._list_frame.grid_columnconfigure(0, weight=1)

    def _refresh_list(self):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._visible_passwords.clear()

        query = self._search_var.get().lower() if hasattr(self, "_search_var") else ""
        entries = [(k, v) for k, v in self._vault.items()
                   if query in k.lower() or query in v.get("username", "").lower()]

        if not entries:
            ctk.CTkLabel(self._list_frame, text="nessuna voce trovata.",
                         text_color="gray").grid(row=0, column=0, pady=40)
        else:
            for i, (site, data) in enumerate(sorted(entries)):
                self._add_entry_row(i, site, data)

        self._count_label.configure(text=f"{len(self._vault)} voce/i")

    def _add_entry_row(self, row_idx: int, site: str, data: dict):
        frame = ctk.CTkFrame(self._list_frame, corner_radius=10)
        frame.grid(row=row_idx, column=0, sticky="ew", pady=5, padx=4)
        frame.grid_columnconfigure(1, weight=1)

        # icona
        initial = site[0].upper() if site else "?"
        badge = ctk.CTkLabel(frame, text=initial, width=42, height=42,
                             fg_color=("#3b82f6", "#1d4ed8"), corner_radius=8,
                             font=ctk.CTkFont(size=16, weight="bold"))
        badge.grid(row=0, column=0, rowspan=2, padx=(12, 10), pady=10)

        ctk.CTkLabel(frame, text=site, font=ctk.CTkFont(size=14, weight="bold"),
                     anchor="w").grid(row=0, column=1, sticky="w", padx=4)
        ctk.CTkLabel(frame, text=data.get("username", ""), text_color="gray",
                     font=ctk.CTkFont(size=12), anchor="w").grid(row=1, column=1, sticky="w", padx=4)

        # campo password
        pwd_var = ctk.StringVar(value="*" * 12)
        pwd_label = ctk.CTkLabel(frame, textvariable=pwd_var,
                                 font=ctk.CTkFont(size=12, family="Courier"),
                                 text_color="gray", anchor="w")
        pwd_label.grid(row=0, column=2, rowspan=2, padx=8)

        show_state = {"visible": False}

        def toggle_show(s=site, pv=pwd_var, st=show_state):
            st["visible"] = not st["visible"]
            pv.set(self._vault[s]["password"] if st["visible"] else "*" * 12)

        ctk.CTkButton(frame, text="👁", width=34, height=30, fg_color="transparent",
                      hover_color=("gray85", "gray25"),
                      command=toggle_show).grid(row=0, column=3, rowspan=2, padx=2)

        ctk.CTkButton(frame, text="📋", width=34, height=30, fg_color="transparent",
                      hover_color=("gray85", "gray25"),
                      command=lambda s=site: self._copy_password(s)).grid(row=0, column=4, rowspan=2, padx=2)

        ctk.CTkButton(frame, text="✏️", width=34, height=30, fg_color="transparent",
                      hover_color=("gray85", "gray25"),
                      command=lambda s=site: self._open_edit_dialog(s)).grid(row=0, column=5, rowspan=2, padx=2)

        ctk.CTkButton(frame, text="🗑", width=34, height=30, fg_color="transparent",
                      hover_color=("gray85", "gray25"),
                      command=lambda s=site: self._delete_entry(s)).grid(row=0, column=6, rowspan=2, padx=(2, 10))

    def _copy_password(self, site: str):
        pwd = self._vault[site]["password"]
        pyperclip.copy(pwd)
        messagebox.showinfo("copiato", f"password per '{site}' copiata negli appunti!")

    def _delete_entry(self, site: str):
        if messagebox.askyesno("conferma", f"eliminare la voce per '{site}'?"):
            del self._vault[site]
            save_vault(self._vault, self._key)
            self._refresh_list()

    def _open_add_dialog(self, prefill_site="", prefill_user="", prefill_pwd="", edit=False):
        dialog = ctk.CTkToplevel(self)
        dialog.title("modifica voce" if edit else "aggiungi voce")
        dialog.geometry("400x360")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)

        # sito
        ctk.CTkLabel(dialog, text="sito / app", font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", padx=24, pady=(20, 2))
        site_e = ctk.CTkEntry(dialog, width=340, height=38)
        site_e.insert(0, prefill_site)
        site_e.grid(row=1, column=0, padx=24)
        if edit:
            site_e.configure(state="disabled")

        # email / nome utente
        ctk.CTkLabel(dialog, text="email / nome utente", font=ctk.CTkFont(size=14)).grid(row=2, column=0, sticky="w", padx=24, pady=(12, 2))
        user_e = ctk.CTkEntry(dialog, width=340, height=38)
        user_e.insert(0, prefill_user)
        user_e.grid(row=3, column=0, padx=24)

        # password
        ctk.CTkLabel(dialog, text="password", font=ctk.CTkFont(size=14)).grid(row=4, column=0, sticky="w", padx=24, pady=(12, 2))
        pwd_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        pwd_frame.grid(row=5, column=0, padx=24)
        pwd_e = ctk.CTkEntry(pwd_frame, width=290, height=38, show="*")
        pwd_e.insert(0, prefill_pwd)
        pwd_e.grid(row=0, column=0)

        def gen():
            pwd_e.delete(0, "end")
            pwd_e.insert(0, generate_password())

        ctk.CTkButton(pwd_frame, text="⚡", width=38, height=38, command=gen).grid(row=0, column=1, padx=(4, 0))

        def save():
            site = site_e.get().strip()
            user = user_e.get().strip()
            pwd = pwd_e.get()
            if not site or not pwd:
                messagebox.showwarning("attenzione", "sito e password obbligatori.", parent=dialog)
                return
            if site in self._vault and not edit:
                messagebox.showwarning("attenzione", f"'{site}' esiste già.", parent=dialog)
                return
            self._vault[site] = {"username": user, "password": pwd}
            save_vault(self._vault, self._key)
            self._refresh_list()
            dialog.destroy()

        ctk.CTkButton(dialog, text="salva", width=340, height=40,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=save).grid(row=6, column=0, padx=24, pady=20)
        dialog.bind("<Return>", lambda e: save())

    def _open_edit_dialog(self, site: str):
        data = self._vault[site]
        self._open_add_dialog(prefill_site=site, prefill_user=data.get("username", ""),
                              prefill_pwd=data.get("password", ""), edit=True)

    def _open_generator(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("generatore password")
        dialog.geometry("360x260")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(dialog, text="lunghezza", font=ctk.CTkFont(size=13)).grid(row=0, column=0, pady=(20, 4))

        length_var = ctk.IntVar(value=16)
        length_label = ctk.CTkLabel(dialog, text="16", font=ctk.CTkFont(size=13, weight="bold"))
        length_label.grid(row=1, column=0)

        def update_label(v):
            length_label.configure(text=str(int(float(v))))

        ctk.CTkSlider(dialog, from_=8, to=48, variable=length_var,
                      command=update_label, width=280).grid(row=2, column=0, pady=6)

        pwd_var = ctk.StringVar(value=generate_password(16))
        pwd_display = ctk.CTkEntry(dialog, textvariable=pwd_var, width=300, height=40,
                                   font=ctk.CTkFont(size=13, family="Courier"), justify="center")
        pwd_display.grid(row=3, column=0, padx=24, pady=12)

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.grid(row=4, column=0)

        ctk.CTkButton(btn_frame, text="genera", width=140,
                      command=lambda: pwd_var.set(generate_password(length_var.get()))).grid(row=0, column=0, padx=6)
        ctk.CTkButton(btn_frame, text="copia", width=140,
                      command=lambda: (pyperclip.copy(pwd_var.get()),
                                       messagebox.showinfo("copiato", "password copiata!"))).grid(row=0, column=1, padx=6)

    def _change_master(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("cambia master password")
        dialog.geometry("380x300")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)

        for i, (label, attr) in enumerate([("vecchia password", "_old"), ("nuova password", "_new"), ("conferma nuova", "_conf")]):
            ctk.CTkLabel(dialog, text=label).grid(row=i*2, column=0, sticky="w", padx=24, pady=(14, 2))
            e = ctk.CTkEntry(dialog, width=320, height=38, show="●")
            e.grid(row=i*2+1, column=0, padx=24)
            setattr(dialog, attr, e)

        def do_change():
            salt = get_or_create_salt()
            if not verify_master(dialog._old.get(), salt):
                messagebox.showerror("errore", "vecchia password errata.", parent=dialog)
                return
            np, nc = dialog._new.get(), dialog._conf.get()
            if np != nc:
                messagebox.showerror("errore", "le nuove password non coincidono.", parent=dialog)
                return
            if len(np) < 8:
                messagebox.showerror("errore", "almeno 8 caratteri.", parent=dialog)
                return
            save_master_hash(np, salt)
            self._key = derive_key(np, salt)
            save_vault(self._vault, self._key)
            messagebox.showinfo("ok", "master password aggiornata.")
            dialog.destroy()

        ctk.CTkButton(dialog, text="cambia", width=320, height=40,
                      command=do_change).grid(row=6, column=0, padx=24, pady=20)


# main
def main():
    login = LoginWindow()
    login.mainloop()
    key, vault = login.get_result()
    if key is None:
        return
    app = PasswordManagerApp(key, vault)
    app.mainloop()

if __name__ == "__main__":
    main()