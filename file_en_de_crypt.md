```
# Sure! Below is a Python script for a simple encrypted file management system that can:

# - Encrypt and decrypt files.
# - List encrypted files.
# - Delete encrypted files.

# It uses the `cryptography` library (`pip install cryptography`) and basic CLI interface.  
# **For demo purposes, symmetric encryption with a password-derived key is used.**
```
```python name=encrypted_file_manager.py
import os
import sys
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from getpass import getpass

STORAGE_DIR = "encrypted_storage"
SALT_FILE = ".salt"

def _init_storage():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    salt_path = os.path.join(STORAGE_DIR, SALT_FILE)
    if not os.path.exists(salt_path):
        with open(salt_path, "wb") as f:
            f.write(os.urandom(16))

def _get_salt():
    with open(os.path.join(STORAGE_DIR, SALT_FILE), "rb") as f:
        return f.read()

def _derive_key(password: str):
    salt = _get_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(src_path, password):
    _init_storage()
    key = _derive_key(password)
    fernet = Fernet(key)
    filename = os.path.basename(src_path)
    dst_path = os.path.join(STORAGE_DIR, filename + ".enc")
    with open(src_path, "rb") as fr:
        data = fr.read()
    enc_data = fernet.encrypt(data)
    with open(dst_path, "wb") as fw:
        fw.write(enc_data)
    print(f"Encrypted and stored as {dst_path}")

def decrypt_file(filename, password, outpath=None):
    _init_storage()
    key = _derive_key(password)
    fernet = Fernet(key)
    enc_path = os.path.join(STORAGE_DIR, filename)
    if not enc_path.endswith(".enc"):
        enc_path += ".enc"
    with open(enc_path, "rb") as fr:
        enc_data = fr.read()
    data = fernet.decrypt(enc_data)
    if outpath is None:
        outpath = filename.replace(".enc", ".dec")
    with open(outpath, "wb") as fw:
        fw.write(data)
    print(f"Decrypted and saved as {outpath}")

def list_files():
    _init_storage()
    files = [f for f in os.listdir(STORAGE_DIR) 
             if f.endswith(".enc")]
    print("Encrypted files:")
    for f in files:
        print(" -", f)

def delete_file(filename):
    _init_storage()
    path = os.path.join(STORAGE_DIR, filename)
    if not path.endswith(".enc"):
        path += ".enc"
    try:
        os.remove(path)
        print(f"Deleted {path}")
    except FileNotFoundError:
        print(f"No such file: {path}")

def usage():
    print("Encrypted File Manager")
    print("Usage:")
    print("  python encrypted_file_manager.py encrypt <source_file>")
    print("  python encrypted_file_manager.py decrypt <filename.enc> [output_file]")
    print("  python encrypted_file_manager.py list")
    print("  python encrypted_file_manager.py delete <filename.enc>")

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "encrypt" and len(sys.argv) == 3:
        password = getpass("Password: ")
        encrypt_file(sys.argv[2], password)
    elif cmd == "decrypt" and (len(sys.argv) == 3 or len(sys.argv) == 4):
        password = getpass("Password: ")
        out = sys.argv[3] if len(sys.argv) == 4 else None
        decrypt_file(sys.argv[2], password, out)
    elif cmd == "list":
        list_files()
    elif cmd == "delete" and len(sys.argv) == 3:
        delete_file(sys.argv[2])
    else:
        usage()

if __name__ == "__main__":
    main()
```

## **How to use:**

```sh
python encrypted_file_manager.py encrypt secret.txt
python encrypted_file_manager.py decrypt secret.txt.enc
python encrypted_file_manager.py list
python encrypted_file_manager.py delete secret.txt.enc
```

## **Requirements:**  
## Install via:  
```sh
pip install cryptography
```
