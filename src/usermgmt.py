from string import printable
from random import choice
import passlib.hash as plh
import sqlite3


from src.UserExceptions import (
    PasswordLengthException,
    PasswordIllegalCharException,
    PasswordCommonException,
    PasswordLackingCharsException,
    UsernameTakenException
)

from src.keymgmt import generate_keypair, encrypt_privkey, decrypt_privkey

ALLOWED_PASS_CHARS = [i for i in printable[:89]]

def generate_salt():
    return "".join([choice(ALLOWED_PASS_CHARS) for _ in range(16)]).encode()

def connect_to_db():
    db = sqlite3.connect("test.db")
    sql = db.cursor()
    print(sql.execute("SELECT * FROM USERS").fetchall())
    return db, sql

# char ent for 89 symbols ~= 6.47
# 12 char password ~= 77 in entropy 
def validate_password(password:str):
    if len(password) < 12:
        # return 1
        raise PasswordLengthException('Password too short!')
    for ch in password:
        if ch not in ALLOWED_PASS_CHARS:
            raise PasswordIllegalCharException('Password contains illegal characters!')
    data = open("files/popular_passwords.txt", "r").readlines()
    for pas in data:
        if password.strip() == pas.strip():
            raise PasswordCommonException('Password found in list of popular passwords!')
    
    lacking = ""

    for id, x in enumerate([ALLOWED_PASS_CHARS[:10], ALLOWED_PASS_CHARS[36:62], ALLOWED_PASS_CHARS[62:]]):
        n = 0
        for ch in password:
            if ch in x:
                n += 1
        match id:
            case 2:
                if n < 2:
                    lacking += "at least 2 special characters;"
            case 1 :
                if n < 2:
                    lacking += "at least 2 capital letters;"
            case 0:
                if n < 1:
                    lacking += "at least 1 number;"
                    
    lacking = lacking.rsplit(";",1)[0]

    if len(lacking) != 0:
        raise PasswordLackingCharsException(lacking)
    return 0

def write_user(username:str, password:str):
    ret:int

    ret = validate_password(password)

    if check_username_taken(username):
        return

    salt = generate_salt()
    hasher = plh.argon2.using(salt=salt, hash_len=47)    
    ghash = hasher.hash(password)

    rsa_keypair = generate_keypair()

    # print(salt, ghash)
    
    keysalt = generate_salt()

   

    priv_key = encrypt_privkey(salt=keysalt, keypair=rsa_keypair, password=password)

    # print(priv_key, "\n\n")
    # print(priv_key.decode("unicode_escape"))

    # print(username, salt, ghash, sep="\n")
        

    db, sql = connect_to_db()

    try:
        sql.execute("INSERT INTO USERS (username, password, pubkey, privkey) VALUES (?,?,?,?)", (username, salt.decode() + "|" + ghash.split(",p=", 1)[1], rsa_keypair.public_key().export_key().decode(), priv_key,))
        db.commit()
        ret = 0
    except Exception as e:
        print("User registration - unknown exception occured!\n", e)
        ret = 9


    # print("\n\n============= FINAL CHECK - User registration =============")

    # print("ret value:", ret)

    # print("users data:", sql.execute("SELECT * FROM USERS").fetchall())

    db.close()
    return ret

def check_username_taken(username):
    db, sql = connect_to_db()

    try:
        sql.execute("SELECT COUNT(*) FROM users WHERE username = (?)", (username,))
        number = sql.fetchall()[0][0]
        # print("================", number, "================")
        if number != 0:
            raise UsernameTakenException
    except UsernameTakenException:
        db.close()
        raise UsernameTakenException
    except Exception as e:
        # print("Uncpecified exception!")
        # print(e)
        db.close()
        return True
    
    db.close()
    return False


def check_hash(salt:bytes, ahash:str, passw:str, enc_key:bytes):
    hasher = plh.argon2.using(salt=salt, hash_len=47)    
    gh = hasher.hash(passw)
    if gh.split(",p=", 1)[1] == ahash:
        return True, decrypt_privkey(passw, enc_key)
    else:
        return False, None

def login_user(username, password):
    db, sql = connect_to_db()
    try:
        sql.execute("SELECT * FROM users WHERE username = ?", (username,))
    except:
        db.close()
        return False

    ret = sql.fetchall()
    salt, acthash = str(ret[0][1]).split("|")
    enc_key = ret[0][3]
    # print(salt, acthash, sep="\n")

    db.close()
    return check_hash(salt.encode(), acthash, password, enc_key)