from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Cipher import AES
from passlib.hash import argon2
from base64 import b64decode

def generate_keypair():
    rsa_keys = RSA.generate(2048)
    return rsa_keys


def nullpadding(data, length=16):
    return data + b"\x00"*(length-len(data) % length) 

def encrypt_privkey(salt:bytes, password:str, keypair:RSA):
    key = b64decode(argon2.using(rounds=10, parallelism=6, memory_cost=262144, salt=salt).hash(password).rsplit("$", 1)[1] + '==')
    return salt + b'|' + chr(16-len(keypair.export_key()) % 16).encode() + AES.new(key, mode=AES.MODE_CBC, iv=salt).encrypt(nullpadding(keypair.export_key()))

def decrypt_privkey(password:str, enc_key:bytes):
    (salt, privkey) = enc_key.split(b"|", 1)
    key = b64decode(argon2.using(rounds=10, parallelism=6, memory_cost=262144,salt=salt).hash(password).rsplit("$", 1)[1] + '==')
    return AES.new(key, mode=AES.MODE_CBC, iv=salt).decrypt(privkey[1:])[:-privkey[0]]

def encrypt_secret(secret:bytes, pub_key:bytes):
    return PKCS1_OAEP.new(RSA.import_key(pub_key)).encrypt(secret)

def decrypt_secret(secret:bytes, pr_key:bytes):
    return PKCS1_OAEP.new(RSA.import_key(pr_key)).decrypt(secret).decode()