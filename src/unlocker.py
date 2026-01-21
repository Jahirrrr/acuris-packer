#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ACURIS RECOVERY TOOL
--------------------
Decryption utility to restore original binaries from .dat recovery files.
"""

import sys
import os
import json
import base64
import zlib
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password_str, salt):
    """Reconstructs the encryption key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password_str.encode()))

def recover_executable(recovery_file):
    print("="*60)
    print("🔓 ACURIS RECOVERY TOOL")
    print("="*60)

    if not os.path.exists(recovery_file):
        print(f"❌ Error: Recovery file '{recovery_file}' not found.")
        return

    try:
        with open(recovery_file, "r") as f:
            data = json.load(f)
        
        salt_b64 = data.get("salt")
        payload_b64 = data.get("payload")
        original_name = "Recovered_" + os.path.basename(data.get("original_filename", "app.exe"))
        
        print(f"[+] Recovery file loaded.")
        print(f"[+] Output target: {original_name}")
        
    except Exception as e:
        print(f"❌ Error: Corrupted recovery file. ({str(e)})")
        return

    pwd = getpass.getpass("🔑 Enter Original Password: ")

    try:
        print("[+] Decrypting...")
        salt = base64.b64decode(salt_b64)
        encrypted_bytes = base64.b64decode(payload_b64)
        
        key = derive_key(pwd, salt)
        f = Fernet(key)
        
        # Decrypt & Decompress
        decrypted_bytes = f.decrypt(encrypted_bytes)
        original_exe = zlib.decompress(decrypted_bytes)
        
        with open(original_name, "wb") as f:
            f.write(original_exe)
            
        print("\n✅ SUCCESS!")
        print(f"   Original file restored: '{original_name}'")
        
    except Exception:
        print("\n❌ FAILED! Incorrect password or corrupted data.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python unlocker.py <RECOVERY_FILE.dat>")
    else:
        recover_executable(sys.argv[1])