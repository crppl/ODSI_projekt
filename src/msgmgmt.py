from src.attachments import add_attachment
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def send_message_TEST(prkey:bytes, message:str, attachments=None):
    print("TODO - implement attachments")
    
    keypair = RSA.import_key(prkey)
    print(len(keypair.export_key()))

    # print(keypair, message, sep="\n---\n")

    msg = message.encode() 
    aeskey = get_random_bytes(32)
    iv = get_random_bytes(16)

    encrypter = AES.new(key=aeskey, mode=AES.MODE_CBC, iv=iv)    

    print(len(msg))

    hashe = SHA256.new(msg)
    hashe.update(b'asd')
    print(hashe.hexdigest())
    sign = pkcs1_15.new(keypair).sign(hashe)

    print(sign, len(sign))

    print(len(msg+sign))

    # cipher = PKCS1_OAEP.new(keypair, hashAlgo=SHA256)
    # enc_msg = cipher.encrypt(sign)

    enc_msg = keypair.encrypt(msg + sign)

    print(enc_msg)

    cipher = PKCS1_OAEP.new(keypair)

    unenc = cipher.decrypt(enc_msg)
    (unenc_msg, sign2) = (unenc[:-256], unenc[-256:])
    
    pkcs1_15.new(keypair).verify(hashe, sign2)

    print(unenc_msg)

    pass
            
    
    