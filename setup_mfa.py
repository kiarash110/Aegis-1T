import pyotp
import qrcode
import os
from dotenv import set_key

def setup_vault_mfa():
    """
    Generates a unique MFA secret and a QR code for the Aegis-1T Vault.
    Uses 'set_key' to maintain a clean and reliable .env file.
    """
    print("--- 🛡️ Aegis-1T: Security Initialization ---")
    
    # 1. Generate a high-entropy 32-character base32 secret
    secret = pyotp.random_base32()
    
    # 2. Configure TOTP labels
    # These appear in your phone's app so you know which code is which
    issuer = "Aegis-1T Vault"
    account_name = "Admin@Local"
    
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)

    # 3. Generate QR Code image
    print("[+] Generating secure QR code...")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_filename = "mfa_setup.png"
    img.save(qr_filename)
    
    # 4. Save secret to .env file professionally
    # This prevents duplicate lines and handles file creation automatically
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
    print("⚠️  CRITICAL: Delete 'mfa_setup.png' after you scan it!")
    print("="*40)

if __name__ == "__main__":
    setup_vault_mfa()
