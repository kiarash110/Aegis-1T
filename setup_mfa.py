import pyotp
import qrcode
import os

def setup_vault_mfa():
    """
    Generates a unique MFA secret and a QR code for the Aegis-1T Vault.
    This links your physical smartphone to the cryptographic vault.
    """
    print("🛡️ Aegis-1T: Multi-Factor Authentication Setup")
    print("----------------------------------------------")

    # 1. Generate a secure, random Base32 secret key
    # This key is the 'seed' that generates your 6-digit codes
    secret = pyotp.random_base32()
    
    # 2. Configure the labels for the Authenticator App
    # Issuer = The name of your software
    # Name = Your specific identity or machine ID
    issuer = "Aegis-1T Vault"
    account_name = "Admin@LocalHost" 

    # 3. Create the provisioning URI (the data inside the QR code)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_name, 
        issuer_name=issuer
    )
    
    # 4. Generate the QR Code image
    print("[+] Generating secure QR code...")
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 5. Save the image and the secret backup
    img.save("mfa_setup.png")
    
    # We save the secret to a .env file so the main vault can read it later
    with open(".env", "a") as f:
        f.write(f"\nMFA_SECRET={secret}")

    print("\n✅ SUCCESS!")
    print(f"1. Your Secret Key is: {secret}")
    print(f"2. A file 'mfa_setup.png' has been created in this folder.")
    print("3. SCAN this image with Google Authenticator or Aegis MFA.")
    print("-" * 46)
    print("⚠️  IMPORTANT: Delete 'mfa_setup.png' after you scan it!")

if __name__ == "__main__":
    setup_vault_mfa()
