from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# from usermgmt import connect_to_db


def generateKeypair():
    rsa_keys = RSA.generate(2048)
    return rsa_keys

