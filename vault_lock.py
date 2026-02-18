import json
import os
import base64
import maskpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

def lock_the_vault():
    print("--- Aegis-1T Vault Lockdown ---")
    
    # 1. Anti-Keylogger Input
    # This prevents the password from showing in the terminal
    password = maskpass.advpass(prompt="CREATE MASTER PASSPHRASE: ", mask="*")
    confirm = maskpass.advpass(prompt="CONFIRM MASTER PASSPHRASE: ", mask="*")

    if password != confirm:
        print("\n[❌] Passwords do not match. Lockdown aborted.")
        return

    # 2. Key Derivation (Argon2id)
    # We use a random salt so two people with the same password have different keys.
    salt = get_random_bytes(16)
    
    # This process is "memory-hard" to stop GPU brute-force attacks
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,           # Passages through memory
        memory_cost=65536,     # Uses 64MB of RAM (prevents mass-cracking)
        parallelism=4,         # Uses 4 threads
        hash_len=32,           # Produces a 256-bit key
        type=Type.ID           # Argon2id variant
    )

    # 3. Read the .env file
    if not os.path.exists(".env"):
        print("\n[❌] Error: .env file not found. Nothing to lock!")
        return

    with open(".env", "rb") as f:
        plaintext = f.read()

    # 4. AES-256-GCM Encryption
    # GCM mode provides 'Authenticated Encryption' (it knows if it's been tampered with)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # 5. Build the Vault JSON
    vault_data = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    # 6. Save and Destroy
    with open(".env.vault", "w") as f:
        json.dump(vault_data, f)

    # Securely delete the original .env
    os.remove(".env")
    
    print("\n[🔒] SUCCESS: .env.vault created.")
    print("[!] ALERT: Original .env file has been deleted for security.")

if __name__ == "__main__":
    lock_the_vault()
