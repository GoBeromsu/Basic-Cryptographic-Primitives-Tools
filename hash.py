import hashlib

m = input("암호화할 메시지를 입력하세요: ") # 메세지 m 입력 받음

# SHA-512 암호화
hash_object = hashlib.sha512(m.encode())
hash_value = hash_object.hexdigest()

print(hash_value)
