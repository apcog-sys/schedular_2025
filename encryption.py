import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate key from password and salt
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt message and return salt:ciphertext string
def encrypt_to_qr_string(message: str, password: str) -> str:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(message.encode())
    # Combine salt and token for QR storage
    return f"{base64.b64encode(salt).decode()}:{token.decode()}"

# Decrypt from salt:ciphertext string
def decrypt_from_qr_string(data: str, password: str) -> str:
    try:
        salt_b64, token = data.split(":")
        salt = base64.b64decode(salt_b64)
        key = generate_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(token.encode()).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

# CLI
def main():
    print("1. Encrypt to QR String")
    print("2. Decrypt from QR String")
    choice = input("Choose an option (1/2): ")

    if choice == "1":
        message = input("Enter message to encrypt: ")
        password = input("Enter password: ")
        qr_data = encrypt_to_qr_string(message, password)
        print(f"\n📦 QR String (store in QR code):\n{qr_data}")

    elif choice == "2":
        qr_data = input("Enter QR string (salt:ciphertext): ")
        password = input("Enter password: ")
        try:
            decrypted_message = decrypt_from_qr_string(qr_data, password)
            print(f"\n🔓 Decrypted message: {decrypted_message}")
        except ValueError as e:
            print(e)

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
