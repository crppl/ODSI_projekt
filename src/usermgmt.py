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

ALLOWED_PASS_CHARS = [i for i in printable[:89]]

def generate_salt():
    return "".join([choice(printable[:89]) for _ in range(16)])

def connect_to_db():
    db = sqlite3.connect("test.db")
    return db, db.cursor()


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
                    # raise PasswordLackingCharsException('Password is lacking special!')
            case 1 :
                if n < 2:
                    lacking += "at least 2 capital letters;"
                    # raise PasswordLackingCharsException('Password is lacking capital letters!')
            case 0:
                if n < 1:
                    lacking += "at least 1 number;"
                    # raise PasswordLackingCharsException('Password is lacking numbers!')

    lacking = lacking.rsplit(";",1)[0]

    if len(lacking) != 0:
        raise PasswordLackingCharsException(lacking)
    return 0

def write_user(username, password):
    ret:int

    # print("TODO: password validation error")
    ret = validate_password(password)

    salt = generate_salt()
    hasher = plh.argon2.using(salt=salt, hash_len=47)    
    hash = hasher.hash(password)
    
    db, sql = connect_to_db()

    try:
        check_username_taken(username)
    except UsernameTakenException:
        raise UsernameTakenException
    except:
        ret = 9
        return ret 
        
    try:
        sql.execute("INSERT INTO USERS (username, password) VALUES (?,?)", username, salt + "|" + hash)
        ret = 0
    except:
        ret = 9

    sql.commit()
    db.close()
    return ret

def check_username_taken(username):
    db, sql = connect_to_db()

    try:
        sql.execute("SELECT COUNT(*) FROM USERS WHERE username = ?", username)
        if int(sql.fetchall()[0][0]) != 0:
            raise UsernameTakenException
    except UsernameTakenException:
        db.close()
        raise UsernameTakenException
    except:
        db.close()
        return False
    
    db.close()
    return True
    

