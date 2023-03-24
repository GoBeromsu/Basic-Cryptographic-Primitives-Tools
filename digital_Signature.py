from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
# Key and message to encrypt
key = get_random_bytes(16)
message = bytes(input().encode())

# AES encryption
aes_cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = aes_cipher.encrypt_and_digest(message)
enc = b64encode(ciphertext + aes_cipher.nonce + tag).decode()

# SHA256 hash
hash_obj = SHA256.new(enc.encode())
hash_value = hash_obj.digest()

# RSA signature
private_key = RSA.generate(2048)
rsa_signer = PKCS1_v1_5.new(private_key)
sig = b64encode(rsa_signer.sign(hash_obj)).decode()

# Digital signature
digital_sig = enc + sig

# Extract enc and sig
enc = digital_sig[:len(digital_sig)-344]
sig = digital_sig[len(digital_sig)-344:]

# RSA public key verification
public_key = private_key.publickey()
rsa_verifier = PKCS1_v1_5.new(public_key)
hash1 = b64decode(sig)
if rsa_verifier.verify(hash_obj, hash1):
    verify = 1
else:
    verify = 0

enc = b64decode(enc)
nonce = enc[16:32]
tag = enc[32:]
ciphertext = enc[:16]
aes_cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = aes_cipher.decrypt(ciphertext)

print(verify)
print(plaintext.decode())