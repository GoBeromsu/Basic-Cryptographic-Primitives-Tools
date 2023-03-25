from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad  # 패딩 모듈을 import합니다.

# Generate a new private/public key pair
key = RSA.generate(2048)
priv_key = key.export_key()
pub_key = key.publickey().export_key()

# Generate a random IV and key for AES encryption
iv = get_random_bytes(16)
key_aes = get_random_bytes(32)

# Message to be encrypted
message = b'This is a 3333secret message'

# Encrypt the message using AES-CBC
cipher = AES.new(key_aes, AES.MODE_CBC, iv=iv)
# 암호화된 메시지의 길이가 16의 배수가 되도록 패딩합니다.
enc = cipher.encrypt(pad(message, AES.block_size))

# Sign the encrypted message using RSA
hash_obj = SHA256.new(enc)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(priv_key))
sig = cipher_rsa.encrypt(hash_obj.digest())

# Combine the encrypted message and signature
digital_sig = enc + sig

# Decrypt the message
hash1 = PKCS1_OAEP.new(RSA.import_key(priv_key)).decrypt(digital_sig[len(enc):])
hash2 = SHA256.new(enc).digest()
if hash1 == hash2:
    print('Hashes match. Decryption successful.')
    cipher = AES.new(key_aes, AES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(enc), AES.block_size)
    print('Decrypted message:', decrypted_message)
else:
    print('Hashes do not match. Decryption unsuccessful.')
