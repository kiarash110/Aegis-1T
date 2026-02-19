import os, pyotp, json, base64, maskpass, time
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# --- CORE CRYPTO CONFIGURATION ---
MEM_COST, TIME_COST, PARALLELISM, SALT_SIZE = 204800, 4, 4, 16

def select_buffer_mode(task_name):
    """Change #5 & #6: Performance Profile Selector with RAM warnings"""
    print(f"\n🚀 SELECT SPEED FOR {task_name.upper()}:")
    print(" [1] Standard (16MB Buffer)  - RAM Usage: ~100MB")
    print(" [2] Extreme  (512MB Buffer) - RAM Usage: ~1.2GB")
    print(" [3] NITRO    (1.5GB Buffer) - RAM Usage: ~3.5GB+")
    
    choice = input(f"👉 Select {task_name} Mode (1/2/3): ")
    if choice == '3':
        print("🔥 NITRO ENABLED: Ensure you have 16GB+ System RAM available.")
        return 1536 * 1024 * 1024
    if choice == '2':
        return 512 * 1024 * 1024
    return 16 * 1024 * 1024

def display_progress(current, total, start_time):
    """Change #2: Progress bar with MB/s and ETA"""
    elapsed = time.time() - start_time
    percent = (current / total) * 100
    speed = (current / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    remaining = (total - current) / (current / elapsed) if current > 0 else 0
    bar = '█' * int(30 * current // total) + '-' * (30 - int(30 * current // total))
    print(f"\r|{bar}| {percent:.1f}% - {speed:.2f} MB/s - ETA: {int(remaining)}s ", end='')

def secure_shred(file_path):
    """Change #1 & #8: Triple-confirm shredder with independent speed selection"""
    print(f"\n\n🧹 SHREDDER INITIALIZED")
    shred_buffer = select_buffer_mode("Shredding")
    
    print(f"\n⚠️  CRITICAL: Shredding will permanently destroy: {file_path.name}")
    if input("👉 Confirm Shredding? (y/n): ").lower() != 'y': return print("🚫 Canceled.")
    if input("👉 ARE YOU SURE? (y/n): ").lower() != 'y': return print("🚫 Canceled.")
    if input("👉 Final warning: Type 'DELETE' to proceed: ") != 'DELETE': return print("🚫 Canceled.")

    file_size = file_path.stat().st_size
    start_time, processed = time.time(), 0
    print(f"\n🧹 Wiping original file with random bytes...")
    
    try:
        with open(file_path, "wb") as f:
            while processed < file_size:
                chunk = min(shred_buffer, file_size - processed)
                f.write(os.urandom(chunk))
                f.flush()
                os.fsync(f.fileno()) # Forces physical write to the SSD
                processed += chunk
                display_progress(processed, file_size, start_time)
        os.remove(file_path)
        total_time = time.time() - start_time
        print(f"\n✨ SHRED COMPLETE: {total_time:.2f}s | Avg: {(file_size/(1024*1024))/total_time:.2f} MB/s")
    except Exception as e:
        print(f"\n❌ SHREDDING FAILED: {e}")

def unlock_vault(master_password):
    if not os.path.exists(".env.vault"): return None
    try:
        with open(".env.vault", "r") as f: vault = json.load(f)
        salt = base64.b64decode(vault['salt'])
        vault_key = hash_secret_raw(master_password.encode(), salt=salt, time_cost=TIME_COST, 
                                     memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
        cipher = AES.new(vault_key, AES.MODE_GCM, nonce=base64.b64decode(vault['nonce']))
        decrypted = cipher.decrypt_and_verify(base64.b64decode(vault['ciphertext']), base64.b64decode(vault['tag']))
        return {k: v for line in decrypted.decode().split('\n') if '=' in line for k, v in [line.split('=', 1)]}
    except: return None

if __name__ == "__main__":
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*60)
        print("🛡️  AEGIS-1T | VERSION 1.0.2 | PERFORMANCE SUITE")
        print("="*60)
        
        action = input("\n[E]ncrypt, [D]ecrypt, [Q]uit: ").upper()
        if action == 'Q': break
        if action not in ['E', 'D']: continue

        target = Path(input("\n👉 Drag File Here: ").strip().strip('"').strip("'"))
        if not target.exists():
            print("❌ File not found."); time.sleep(2); continue

        # Change #9: Anti-Double Encryption Guard
        if action == 'E' and target.suffix == '.aegis':
            print("\n🛑 ERROR: This file is already encrypted (.aegis).")
            print("Double encryption causes structural corruption and is blocked.")
            time.sleep(4); continue

        # Change #10: Master Password Guard (Min 6 Characters)
        while True:
            print("\n" + "─"*55)
            print("🔒 SECURITY: Passwords show as '*'. Press [L-CTRL] to peek.")
            print("─" * 55)
            master_pass = maskpass.advpass(prompt="🔑 System Master Password: ", mask="*")
            if len(master_pass) >= 6: break
            print("⚠️  Master Password must be at least 6 characters.")

        vault = unlock_vault(master_pass)
        if not vault:
            print("❌ Access Denied."); time.sleep(2); continue

        mfa_secret = vault.get("MFA_SECRET")
        file_pass = maskpass.advpass(prompt="🛡️  File-Specific Password: ", mask="*")
        
        # Performance Mode Selection
        buffer_size = select_buffer_mode("Processing")
        
        # MFA Verification
        if not pyotp.TOTP(mfa_secret).verify(input("\n🛡️  Enter MFA code: ")):
            print("❌ MFA Invalid."); time.sleep(2); continue

        start_time, processed = time.time(), 0
        file_size = target.stat().st_size
        
        try:
            if action == 'E':
                salt = get_random_bytes(SALT_SIZE)
                key = hash_secret_raw(file_pass.encode(), salt=salt, time_cost=TIME_COST, memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
                cipher = AES.new(key, AES.MODE_GCM)
                output_path = target.with_suffix(target.suffix + ".aegis")
                
                with open(target, 'rb') as f_in, open(output_path, 'wb') as f_out:
                    f_out.write(salt)
                    f_out.write(cipher.nonce)
                    while (chunk := f_in.read(buffer_size)):
                        f_out.write(cipher.encrypt(chunk))
                        processed += len(chunk)
                        display_progress(processed, file_size, start_time)
                    f_out.write(cipher.digest())
                
                # Change #7: Completion Report
                duration = time.time() - start_time
                print(f"\n\n✅ ENCRYPTION COMPLETE")
                print(f"📊 Time: {int(duration // 60)}m {int(duration % 60)}s | Speed: {(file_size/(1024*1024))/duration:.2f} MB/s")
                print(f"📦 Final Size: {output_path.stat().st_size / (1024**3):.4f} GB")
                secure_shred(target)

            elif action == 'D':
                with open(target, 'rb') as f_in:
                    salt, nonce = f_in.read(SALT_SIZE), f_in.read(16)
                    data_size = file_size - SALT_SIZE - 32 # Salt + Nonce + Tag
                    key = hash_secret_raw(file_pass.encode(), salt=salt, time_cost=TIME_COST, memory_cost=MEM_COST, parallelism=PARALLELISM, hash_len=32, type=Type.ID)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    output_path = Path(str(target).replace(".aegis", ""))
                    
                    with open(output_path, 'wb') as f_out:
                        while processed < data_size:
                            chunk = f_in.read(min(buffer_size, data_size - processed))
                            f_out.write(cipher.decrypt(chunk))
                            processed += len(chunk)
                            display_progress(processed, data_size, start_time)
                        
                        try:
                            cipher.verify(f_in.read(16))
                            duration = time.time() - start_time
                            print(f"\n\n🔓 DECRYPTION SUCCESSFUL")
                            print(f"📊 Time: {int(duration // 60)}m {int(duration % 60)}s | Speed: {(data_size/(1024*1024))/duration:.2f} MB/s")
                        except:
                            print("\n❌ INTEGRITY FAILURE: Wrong password or corrupt file.")
                            f_out.close(); os.remove(output_path)
        except Exception as e:
            print(f"\n❌ CRITICAL ERROR: {e}")
        
        if input("\n🔄 Task complete. Process another file? (y/n): ").lower() != 'y':
            break
