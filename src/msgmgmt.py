from src.attachments import add_attachment
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

def send_message_TEST(keypair:RSA, message:str, attachments=None):
    print("TODO - implement attachments")
    
    hashe = SHA256.new(message)
    print(hashe)
    sign = pkcs1_15.new(keypair).sign(hashe)

    cipher = PKCS1_OAEP.new(keypair)
    enc_msg = cipher.encrypt(message.encode() + sign)

    print(enc_msg)

    cipher = PKCS1_OAEP.new(keypair)
    unenc = cipher.decrypt(enc_msg)
    (unenc_msg, sign2) = (unenc[:-256], unenc[-256:])
    
    pkcs1_15.new(keypair).vefiry(hashe, sign2)

    print(unenc_msg)


    pass
            
    
    