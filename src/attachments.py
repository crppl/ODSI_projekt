from werkzeug.datastructures.file_storage import FileStorage
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES 
import sqlite3
import os

PEPPER = b'G81ksfnal0192030'

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}
def validate_filename(filename):
    return '.' in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def add_attachment(file:FileStorage, username):
    print(os.getcwd())
    sql = sqlite3.connect("test.db").cursor()
    sql.execute("SELECT password FROM USERS WHERE username = ?", [username])
    sale, hashe = sql.fetchall()[0][0].split("|")
    cipher = AES.new(PEPPER + hashe[::-1].encode("utf-8"), AES.MODE_GCM)
    return cipher.encrypt(file.read())
