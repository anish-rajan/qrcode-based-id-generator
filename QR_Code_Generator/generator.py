import ed25519
import pyqrcode
import png
from pyqrcode import QRCode
import sys

# privKey, pubKey = ed25519.create_keypair()
private_key = b'e21ffeb4072328eddaa435d5a5920422af7dfe7b76fece04391f172b1131b2db'
public_key = b'482a339bb85220be3755fca44f75cc4a4eb88044883fd61a2a30e22d66e99d07'
privKey = ed25519.SigningKey(private_key,encoding='hex')
pubKey = ed25519.VerifyingKey(public_key,encoding='hex')
print("Private key (32 bytes):", privKey.to_ascii(encoding='hex'))
print("Public key (32 bytes): ", pubKey.to_ascii(encoding='hex'))

msg = b'Message for Ed25519 signing'
signature = privKey.sign(msg, encoding='hex')
print("Signature (64 bytes):", signature)

try:
    pubKey.verify(signature, msg, encoding='hex')
    print("The signature is valid.")
except:
    print("Invalid signature!")
  
print(signature)
# Generate QR code
qr_code = pyqrcode.create(signature)
  
# Create and save the svg file naming "myqr.svg"
qr_code.svg("qr_code.svg", scale = 8)
  
# Create and save the png file naming "myqr.png"
qr_code.png('qr_code.png', scale = 6)