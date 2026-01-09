from src.attachments import add_attachment
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from src.usermgmt import connect_to_db
from src.keymgmt import nullpadding

from src.UserExceptions import UserNotFounException

def send_message(sender:str, reciever:str, prkey:bytes, message:str, attachments=None):
    print("TODO - implement attachments")
    
    db, sql = connect_to_db()

    if len(sql.execute("SELECT username FROM user WHERE username = (?)", (reciever, ))).fetchall() == 0:
        raise UserNotFounException("Reciever not found!")

    pubkey:str

    try:
        pubkey = sql.execute("SELECT pubkey FROM users WHERE username = (?)", (reciever, )).fetchall()[0][0]
    except:
        return 1

    sender_keypair = RSA.import_key(prkey)
    reciever_keypair = RSA.import_key(pubkey)

    msg = message.encode() 
    aeskey = get_random_bytes(32)
    iv = get_random_bytes(16)

    encrypter = AES.new(key=aeskey, mode=AES.MODE_CBC, iv=iv)    
    enc_msg_aes = encrypter.encrypt(nullpadding(message.encode()))

    hashe = SHA512.new(msg)
    hashe.update(b'asd')
    sign = pkcs1_15.new(sender_keypair).sign(hashe)

    cipher = PKCS1_OAEP.new(reciever_keypair, hashAlgo=SHA512)
    enc_msg_rsa = cipher.encrypt(aeskey + iv) + sign

    sql.execute("INSERT INTO MESSAGES (recievee, sendee, message_encrypted, encrypted_message) VALUES (?,?,?,?)", (sender, reciever, enc_msg_aes, enc_msg_rsa,))
    db.commit()
    db.close()

    return 0

def decrypt_message(msg_id:int, enc_msg_rsa:bytes, enc_msg_aes:bytes, prkey:bytes):

    print("TODO - implement attachments")

    db, sql = connect_to_db()
    
    # if len(sql.execute("SELECT username FROM user WHERE username = (?)", (reciever, ))).fetchall() == 0:
        # raise UserNotFounException("Reciever not found!")

    pubkey:str
    message_all:tuple

    try:
        message_all = sql.execute("SELECT * FROM MESSAGES WHERE msgid = (?)", (msg_id, )).fetchall()[0]
        pubkey = sql.execute("SELECT pubkey FROM users WHERE username = (?)", message_all[1]).fetchall()[0][0]
    except:
        return 0



    reciever_keypair = RSA.import_key(prkey)
    sender_keypair = RSA.import_key(pubkey)

    cipher = PKCS1_OAEP.new(reciever_keypair, hashAlgo=SHA512)
    
    (enc_aeskey, sign2) = (enc_msg_rsa[:-256], enc_msg_rsa[-256:])

    unenc_aeskey_iv = cipher.decrypt(enc_aeskey)

    (u_aes, u_iv) = (unenc_aeskey_iv[:-16], unenc_aeskey_iv[-16:])

    decrypter = AES.new(u_aes, mode=AES.MODE_CBC, iv=u_iv)

    unenc_msg = decrypter.decrypt(enc_msg_aes)

    hashe = SHA512.new(unenc_msg)

    pkcs1_15.new(sender_keypair).verify(hashe, sign2)

    print(unenc_msg)
    return True