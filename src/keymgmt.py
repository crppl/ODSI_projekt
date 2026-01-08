from Cryptodome.PublicKey import RSA
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id as cptArgon
from Cryptodome.Cipher import AES
from passlib.hash import scrypt
from base64 import b64decode

def generate_keypair():
    rsa_keys = RSA.generate(3072)
    # print(len(rsa_keys.export_key()))
    return rsa_keys

# def encryptPrivKey_readable(salt:bytes, keypair:RSA, password:str):
#     hasher2 = cptArgon(salt=salt, length=32, iterations=1, lanes=4, memory_cost=65536)
#     priv_key_key = hasher2.derive(password.encode())

#     aes_cipher = AES.new(priv_key_key, mode=AES.MODE_GCM)

#     return  aes_cipher.encrypt(keypair.export_key())


def nullpadding(data, length=16):
    return data + b"\x00"*(length-len(data) % length) 

# def encrypt_privkey_BAD(salt:bytes, password:str, keypair:RSA):
#     return chr(16-len(keypair.export_key()) % 16).encode() + AES.new(cptArgon(salt=salt, length=32, iterations=1, lanes=4, memory_cost=65536).derive(password.encode()), mode=AES.MODE_CBC, iv=salt).encrypt(nullpadding(keypair.export_key()))

def encrypt_privkey(salt:bytes, password:str, keypair:RSA):
    key = b64decode(scrypt.using(rounds=20, salt=salt).hash(password).rsplit("$", 1)[1] + '==')
    # print("!!! priv key encryption key!!!", key, key.decode('unicode_escape'), "keylen: " + str(len(key)), sep="\n")
    return salt + b'|' + chr(16-len(keypair.export_key()) % 16).encode() + AES.new(key, mode=AES.MODE_CBC, iv=salt).encrypt(nullpadding(keypair.export_key()))

def decrypt_privkey(password:str, enc_key:bytes):
    (salt, privkey) = enc_key.split(b"|", 1)
    # print(salt, str(privkey[0]))
    # print(privkey[0], type(privkey[0]))
    key = b64decode(scrypt.using(rounds=20, salt=salt).hash(password).rsplit("$", 1)[1] + '==')
    return AES.new(key, mode=AES.MODE_CBC, iv=salt).decrypt(privkey[1:])[:-privkey[0]]
