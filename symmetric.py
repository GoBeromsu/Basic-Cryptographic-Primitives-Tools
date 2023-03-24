from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
# 키 생성
key = RSA.generate(2048)

# 공개키(Pu)와 비공개키(Pr) 추출
Pu = key.publickey()
Pr = key

# 메시지 암호화
def rsa_encrypt(m, Pu):
    cipher = PKCS1_OAEP.new(Pu)
    ciphertext = cipher.encrypt(m)
    return ciphertext

# 암호문 복호화
def rsa_decrypt(ciphertext, Pr):
    cipher = PKCS1_OAEP.new(Pr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# 테스트
def start():
    message = bytes(input().encode())
    ciphertext = rsa_encrypt(message, Pu)
    plaintext = rsa_decrypt(ciphertext, Pr).decode()
    print(f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
    print(f"Plaintext: {plaintext}")
