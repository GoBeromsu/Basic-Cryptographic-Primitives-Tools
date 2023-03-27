from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(m, key, mode):
    iv = get_random_bytes(16)
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
    else:    
        cipher = AES.new(key, mode, iv)
    ciphertext = cipher.encrypt(pad(m, AES.block_size))
    return iv + ciphertext

def aes_decrypt(ciphertext, key, mode):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
    else:
        cipher = AES.new(key, mode, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def start():
    m = bytes(input().encode())
    key = get_random_bytes(16)
    ecb_cipher = aes_encrypt(m, key, AES.MODE_ECB)
    cbc_cipher = aes_encrypt(m, key, AES.MODE_CBC)
    cfb_cipher = aes_encrypt(m, key, AES.MODE_CFB)
    ofb_cipher = aes_encrypt(m, key, AES.MODE_OFB)

    print("ECB ciphertext:", ecb_cipher)
    print("CBC ciphertext:", cbc_cipher)
    print("CFB ciphertext:", cfb_cipher)
    print("OFB ciphertext:", ofb_cipher)

    ecb_plaintext = aes_decrypt(ecb_cipher, key, AES.MODE_ECB)
    cbc_plaintext = aes_decrypt(cbc_cipher, key, AES.MODE_CBC)
    cfb_plaintext = aes_decrypt(cfb_cipher, key, AES.MODE_CFB)
    ofb_plaintext = aes_decrypt(ofb_cipher, key, AES.MODE_OFB)

    print("ECB plaintext:", ecb_plaintext)
    print("CBC plaintext:", cbc_plaintext)
    print("CFB plaintext:", cfb_plaintext)
    print("OFB plaintext:", ofb_plaintext)
