from werkzeug.datastructures.file_storage import FileStorage
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES 
import sqlite3

PEPPER = b'G81ksfnal'

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}
def validate_filename(filename):
    return '.' in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def add_attachment(file:FileStorage, username):
    sql = sqlite3.connect("test.db").cursor()
    sql.execute("SELECT SUBSTR(password, 33) FROM users WHERE username = ?", [username])
    sale, hashe = sql.fetchall()[0][2].split("|")
    cipher = AES(PEPPER + hashe[::-1], AES.MODE_GCM)
    # return cipher.en file.read()
