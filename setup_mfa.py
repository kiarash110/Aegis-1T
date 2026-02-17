# =================================================================
# 🔐 AEGIS-1T: MFA INITIALIZATION & QR GENERATOR
# =================================================================
# DESCRIPTION: Generates the unique "Seed" for the 2FA system.
# SECURITY: High-entropy Base32 secret generation.
# OUTPUT: .env (Private Key) and mfa_setup.png (Scanner Image).
# =================================================================

import pyotp
import qrcode
import os
from dotenv import set_key

def setup_vault_mfa():
    """
    🏗️ THE FOUNDATION
    This function creates the 'Secret Key' that both your computer 
    and your phone app will use to calculate those 6-digit codes.
    """
    print("--- 🛡️ Aegis-1T: Security Initialization ---")
    
    # 1️⃣ GENERATE THE MASTER SEED
    # pyotp.random_base32() creates a 32-character high-entropy string.
    # This is the "Shared Secret" that never leaves your local system.
    secret = pyotp.random_base32()
    
    # 2️⃣ CONFIGURE THE AUTHENTICATOR APP LABEL
    # These strings appear in your Google Authenticator app list 
    # so you don't forget which app this code belongs to.
    issuer = "Aegis-1T Vault"
    account_name = "Admin@Local"
    
    # We build a 'Provisioning URI' - a special URL that tells your 
    # phone app exactly how to set up the connection.
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)

    # 3️⃣ CREATE THE VISUAL "KEY" (QR CODE)
    # Instead of typing a long 32-character code, we turn it into a 
    # QR code for a 1-second scan.
    print("[+] Generating secure QR code...")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    # Save the QR code as a PNG file
    img = qr.make_image(fill_color="black", back_color="white")
    qr_filename = "mfa_setup.png"
    img.save(qr_filename)
    
    # 4️⃣ SAVE TO THE HIDDEN VAULT (.env)
    # We use 'set_key' from python-dotenv because it's safer than 'open().write()'.
    # It checks if the file exists and updates it without messing up other keys.
    env_path = ".env"
    if not os.path.exists(env_path):
        with open(env_path, "w") as f: pass # Create empty file if missing
        
    set_key(env_path, "MFA_SECRET", secret)

    print("\n" + "="*40)
    print("✅ MFA SETUP COMPLETE")
    print("="*40)
    print(f"1. Scan the image: '{qr_filename}'")
    print(f"2. Your backup secret is: {secret}")
    print(f"3. The secret has been locked into your '.env' file.")
    print("-" * 40)
    
    # 🛡️ THE MOST IMPORTANT STEP
    # If a hacker gets this PNG, they can scan it and have your 2FA!
    print("⚠️  CRITICAL: Delete 'mfa_setup.png' after you scan it!")
    print("="*40)

if __name__ == "__main__":
    setup_vault_mfa()
