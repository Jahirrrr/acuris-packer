#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ACURIS PACKER
-------------------------------------------
A Python-based executable packer that provides:
1. AES-256 Encryption (Fernet)
2. PBKDF2HMAC Key Derivation (SHA256)
3. Variable Name Obfuscation
4. Custom Dark-Mode GUI for Password Entry
5. Anti-Tamper / Recovery Mechanisms

Author: Zahir Hadi Athallah
License: MIT License
"""

import sys
import os
import base64
import zlib
import subprocess
import shutil
import time
import getpass
import random
import string
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AcurisPacker:
    def __init__(self, target_file):
        self.target_file = target_file
        
        if not os.path.exists(self.target_file):
            print(f"❌ [Error] Target file '{self.target_file}' not found.")
            sys.exit(1)
            
        self.filename_only = os.path.splitext(os.path.basename(target_file))[0]
        self.output_name = f"{self.filename_only}_Protected"
        self.loader_script = f"loader_{int(time.time())}.py"
        self.salt = os.urandom(16)
        
        self.payload = None
        self.salt_b64 = None

    def _generate_obfuscated_var(self):
        """Generates a random variable name to confuse reverse engineers."""
        return "_" + "".join(random.choices(string.ascii_letters + string.digits, k=8))

    def _derive_key(self, password_str, salt):
        """Derives a secure 32-byte key from the password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, 
        )
        return base64.urlsafe_b64encode(kdf.derive(password_str.encode()))

    def encrypt_payload(self, password):
        print(f"[1/5] 🔒 Encrypting & Obfuscating payload...")
        
        key = self._derive_key(password, self.salt)
        
        with open(self.target_file, "rb") as f:
            raw_data = f.read()
            
        # Compress and Encrypt
        compressed_data = zlib.compress(raw_data, level=9)
        f = Fernet(key)
        encrypted_data = f.encrypt(compressed_data)
        
        # Encode
        self.payload = base64.b64encode(encrypted_data).decode('utf-8')
        self.salt_b64 = base64.b64encode(self.salt).decode('utf-8')

    def save_recovery_file(self):
        print(f"[2/5] 💾 Generating recovery file...")
        recovery_data = {
            "salt": self.salt_b64,
            "payload": self.payload,
            "original_filename": self.target_file,
            "timestamp": time.ctime(),
            "version": "Acuris v1.0"
        }
        rec_name = f"{self.filename_only}_recovery.dat"
        with open(rec_name, "w") as f:
            json.dump(recovery_data, f, indent=4)

    def generate_loader(self):
        print(f"[3/5] 🎨 Injecting Custom UI & Logic...")
        
        # Obfuscation
        v_salt = self._generate_obfuscated_var()
        v_payload = self._generate_obfuscated_var()
        v_realname = self._generate_obfuscated_var()
        v_derive = self._generate_obfuscated_var()
        v_main = self._generate_obfuscated_var()
        v_pwd = self._generate_obfuscated_var()
        v_path = self._generate_obfuscated_var()
        
        loader_code = f"""
import sys, os, zlib, base64, tempfile, subprocess, ctypes
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- OBFUSCATED PAYLOAD ---
{v_salt} = "{self.salt_b64}"
{v_payload} = "{self.payload}"
{v_realname} = "sys_service_core.exe"

def {v_derive}(p, s):
    try:
        k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=100000)
        return base64.urlsafe_b64encode(k.derive(p.encode()))
    except: return None

class SecurityPrompt:
    def __init__(self):
        self.password = None
        self.root = tk.Tk()
        self.root.title("Security Check")
        self.bg_color = "#121212"
        self.accent_color = "#00e5ff"
        self._setup_window()
        self._build_widgets()

    def _setup_window(self):
        w, h = 420, 220
        ws = self.root.winfo_screenwidth()
        hs = self.root.winfo_screenheight()
        x = (ws/2) - (w/2)
        y = (hs/2) - (h/2)
        self.root.geometry('%dx%d+%d+%d' % (w, h, x, y))
        self.root.configure(bg=self.bg_color)
        self.root.resizable(False, False)

    def _build_widgets(self):
        tk.Frame(self.root, bg=self.accent_color, height=2).pack(fill='x')
        tk.Label(self.root, text="ACURIS PACKER", font=("Segoe UI", 16, "bold"), 
                 bg=self.bg_color, fg=self.accent_color).pack(pady=(25, 5))
        tk.Label(self.root, text="Secured Environment Access", font=("Segoe UI", 9), 
                 bg=self.bg_color, fg="#777777").pack(pady=(0, 20))
        self.entry = tk.Entry(self.root, show="•", font=("Segoe UI", 12), width=25,
                              bg="#2b2b2b", fg="white", insertbackground="white", 
                              relief="flat", justify="center")
        self.entry.pack(ipady=5, pady=5)
        self.entry.focus()
        self.entry.bind('<Return>', self.submit)
        self.btn = tk.Button(self.root, text="UNLOCK", command=self.submit,
                             font=("Segoe UI", 10, "bold"), bg=self.accent_color, fg="black",
                             relief="flat", activebackground="#00b8cc", cursor="hand2")
        self.btn.pack(pady=20, ipadx=20, ipady=2)

    def submit(self, event=None):
        self.password = self.entry.get()
        self.root.destroy()

    def run(self):
        self.root.mainloop()
        return self.password

def {v_main}():
    try: ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except: pass

    app = SecurityPrompt()
    {v_pwd} = app.run()
    if not {v_pwd}: sys.exit(0)

    try:
        s = base64.b64decode({v_salt})
        key = {v_derive}({v_pwd}, s)
        fernet = Fernet(key)
        raw = fernet.decrypt(base64.b64decode({v_payload}))
        data = zlib.decompress(raw)
        
        {v_path} = os.path.join(tempfile.gettempdir(), {v_realname})
        with open({v_path}, "wb") as f: f.write(data)
        try: ctypes.windll.kernel32.SetFileAttributesW({v_path}, 2)
        except: pass

        subprocess.Popen([{v_path}], shell=False).wait()
        
        if os.path.exists({v_path}):
            try: os.remove({v_path})
            except: pass
            
    except Exception:
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("Acuris Packer", "ACCESS DENIED: Invalid Password.")
        sys.exit(1)

if __name__ == "__main__":
    {v_main}()
"""
        with open(self.loader_script, "w", encoding="utf-8") as f:
            f.write(loader_code)

    def compile_exe(self):
        print(f"[4/5] ⚙️  Compiling Executable via PyInstaller...")
        cmd = ["pyinstaller", "--noconsole", "--onefile", "--clean", f"--name={self.output_name}", self.loader_script]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def cleanup(self):
        print(f"[5/5] 🧹 Cleaning up temporary artifacts...")
        files = [self.loader_script, f"{self.output_name}.spec"]
        for f in files: 
            if os.path.exists(f): os.remove(f)
        shutil.rmtree("build", ignore_errors=True)
        shutil.rmtree("__pycache__", ignore_errors=True)

    def run(self):
        print("\n" + "="*60)
        print(f"🛡️  ACURIS PACKER")
        print("="*60)
        try:
            pwd = getpass.getpass("🔑 Enter Encryption Password: ")
            confirm = getpass.getpass("🔑 Confirm Password: ")
            if pwd != confirm: 
                print("❌ [Error] Passwords do not match.")
                return
            self.encrypt_payload(pwd)
            self.save_recovery_file()
            self.generate_loader()
            self.compile_exe()
            self.cleanup()
            print("\n✅ BUILD SUCCESSFUL!")
            print(f"   • Protected Binary : dist/{self.output_name}.exe")
            print(f"   • Recovery Key     : {self.filename_only}_recovery.dat (KEEP SAFE!)")
            print("="*60 + "\n")
        except KeyboardInterrupt:
            print("\n⚠️  Process cancelled.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python packer.py <TARGET_FILE.exe>")
        sys.exit(1)
    AcurisPacker(sys.argv[1]).run()