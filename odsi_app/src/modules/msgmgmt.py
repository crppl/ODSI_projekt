from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from base64 import b64encode, b64decode
from werkzeug.datastructures.file_storage import FileStorage

from src.modules.usermgmt import connect_to_db
from src.modules.keymgmt import nullpadding
from src.modules.attachments import transform_attachment, get_attachment

from src.modules.CustomExceptions import UserNotFounException

from datetime import datetime

def prepare_message(title:str, date:str, message:str, attachments:FileStorage=None):
    head = 0
    bmsg = b64encode(b64encode(title.encode()) + b')' + date.encode() + b')' + message.encode())
    if attachments != None and attachments.filename != "":
        head = (head+1)
        attach = transform_attachment(attachments)
        bmsg += (b'|' + attach)
    modulo = 15 - len(bmsg)%16
    head = ((head << 4) + modulo)
    return head.to_bytes(), bmsg
    

def send_message(title:str, sender:str, reciever:str, prkey:bytes, message:str, attachments:FileStorage=None):
    
    db, sql = connect_to_db()

    dejt = datetime.today().date().strftime("%d-%m-%Y")

    if len(sql.execute("SELECT username FROM users WHERE username = (?)", (reciever, )).fetchall()) == 0:
        raise UserNotFounException("Recipient not found!")

    pubkey:str

    try:
        pubkey = sql.execute("SELECT pubkey FROM users WHERE username = (?)", (reciever, )).fetchall()[0][0]
    except:
        return 1

    sender_keypair = RSA.import_key(prkey)
    reciever_keypair = RSA.import_key(pubkey)

    (head, msg) = prepare_message(title, dejt, message, attachments)
    aeskey = get_random_bytes(32)
    iv = get_random_bytes(16)

    encrypter = AES.new(key=aeskey, mode=AES.MODE_CBC, iv=iv)    
    enc_msg_aes = encrypter.encrypt(nullpadding(head+msg))

    hashe = SHA512.new(msg)
    sign = pkcs1_15.new(sender_keypair).sign(hashe)


    cipher = PKCS1_OAEP.new(reciever_keypair, hashAlgo=SHA512)
    enc_test = cipher.encrypt(aeskey+iv)
    enc_msg_rsa = enc_test + sign


    try:
        sql.execute("INSERT INTO MESSAGES (recievee, sendee, message_encrypted, encrypted_message) VALUES (?,?,?,?)", (sender, reciever, enc_msg_aes, enc_msg_rsa,))
    except Exception as e:
        print(e)
    db.commit()
    db.close()
    return 0


def decrypt_message(msg_id:int, prkey:bytes, set_as_read:bool=False):

    db, sql = connect_to_db()
    
    pubkey:str
    message_all:tuple

    try:
        message_all = sql.execute("SELECT * FROM MESSAGES WHERE msgid = (?)", (msg_id, )).fetchall()[0]
        pubkey = sql.execute("SELECT pubkey FROM users WHERE username = (?)", (message_all[1],)).fetchall()[0][0]
    except:
        return 0
    
    if len(message_all) == 0:
        return 0

    msg_id = message_all[0]
    sender = message_all[1]
    enc_msg_rsa = message_all[4]
    enc_msg_aes = message_all[3]

    reciever_keypair = RSA.import_key(prkey)
    sender_keypair = RSA.import_key(pubkey)

    cipher = PKCS1_OAEP.new(reciever_keypair, hashAlgo=SHA512)
    (enc_aeskey, sign) = (enc_msg_rsa[:-256], enc_msg_rsa[-256:])

    unenc_aeskey_iv = cipher.decrypt(enc_aeskey)
    (u_aes, u_iv) = (unenc_aeskey_iv[:-16], unenc_aeskey_iv[-16:])

    decrypter = AES.new(u_aes, mode=AES.MODE_CBC, iv=u_iv)
    unenc_msg = decrypter.decrypt(enc_msg_aes)

    head = unenc_msg[0]
    message = unenc_msg[1:-(head&15)]

    hashe = SHA512.new(message)

    correct_sign = True

    try:
        pkcs1_15.new(sender_keypair).verify(hashe, sign)
    except ValueError:
        correct_sign = False

    read_check = head&32
    attach_check = head&16

    # seeing as "read"
    if not read_check and set_as_read:
        mark_message_as_read(msg_id, prkey)

    attachment = None
    if attach_check:
        (message, attachment) = message.split(b'|', 1)
        (ret_attach_fname, ret_attach) = get_attachment(attachment)
    else:
        ret_attach_fname = None
        ret_attach = None

    (title, dejt, ret_msg) = b64decode(message).split(b')', 2)

    db.close()

    return msg_id, correct_sign, b64decode(title).decode(), dejt.decode(), sender, read_check, ret_msg.decode(), ret_attach_fname, ret_attach


def get_user_msg_ids(username:str):
    db, sql = connect_to_db()
    try:
        ids = sql.execute("SELECT msgid FROM messages WHERE sendee = (?)", (username,)).fetchall()
    except:
        print("TODO - implement except")
        pass
    db.close()
    return [(lambda id:id[0])(id) for id in ids]


def get_user_messages(username:str, prkey:bytes):
    msg_ids = get_user_msg_ids(username)

    ret_messages = [decrypt_message(idd, prkey)[:6] for idd in msg_ids]

    return ret_messages


def get_user_message_id(msg_id:int, prkey:bytes):
    return decrypt_message(msg_id, prkey, set_as_read=True)


def check_message_recipient(username:str, msg_id:int):
    db, sql = connect_to_db()
    
    try:
        recipient_all = sql.execute("SELECT sendee FROM messages WHERE msgid = (?)", (msg_id,)).fetchall()
    except:
        print("write this excption")
        return False

    db.close()

    if len(recipient_all) == 0:
        return False
    else:
        return recipient_all[0][0] == username 
    

def delete_message(msg_id:int):
    db, sql = connect_to_db()
    try:
        sql.execute("DELETE FROM messages WHERE msgid = (?)", (msg_id,))
        db.commit()
    
    except:
        print("write this exception 2")
        return False
    
    db.close()
    return True


def mark_message_as_read(msg_id:int, prkey:bytes):
    db, sql = connect_to_db()
    try:
        message_all = sql.execute("SELECT * FROM messages WHERE msgid = (?)", (msg_id,)).fetchall()[0]
        pubkey = sql.execute("SELECT pubkey FROM users WHERE username = (?)", (message_all[1],)).fetchall()[0][0]
    except Exception as e:
        print("write this exception 3")
        print(e)
        return False
    
    if len(message_all) == 0:
        db.close()
        return False;

    priv_key = RSA.import_key(prkey)
    sender_keypair = RSA.import_key(pubkey)

    enc_msg_rsa = message_all[4]
    enc_msg_aes = message_all[3]


    cipher = PKCS1_OAEP.new(priv_key, hashAlgo=SHA512)
    (enc_aeskey, sign) = (enc_msg_rsa[:-256], enc_msg_rsa[-256:])

    unenc_aeskey_iv = cipher.decrypt(enc_aeskey)
    (u_aes, u_iv) = (unenc_aeskey_iv[:-16], unenc_aeskey_iv[-16:])
    
    decrypter = AES.new(u_aes, mode=AES.MODE_CBC, iv=u_iv)
    unenc_msg = decrypter.decrypt(enc_msg_aes)
    
    head = unenc_msg[0]
    message = unenc_msg[1:-(head&15)]

    hashe = SHA512.new(message)
    pkcs1_15.new(sender_keypair).verify(hashe, sign)

    head |= 32
    reencrypter = None
    try:
        reencrypter = AES.new(u_aes, mode=AES.MODE_CBC, iv=u_iv)
        sql.execute("UPDATE messages SET message_encrypted = (?) WHERE msgid = (?)", (reencrypter.encrypt(head.to_bytes() + unenc_msg[1:]), msg_id,))
        db.commit()
    except Exception as e:
        print(e)
        print("TODO - implement in msgmgmt")
        return False

    del enc_msg_aes, enc_msg_rsa, message_all, pubkey, cipher, enc_aeskey, sign, u_aes, u_iv 
    del unenc_aeskey_iv, decrypter, unenc_msg, head, message, hashe, reencrypter 

    db.close()

    return True