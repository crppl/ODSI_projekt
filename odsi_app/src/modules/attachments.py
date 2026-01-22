from werkzeug.datastructures.file_storage import FileStorage
from base64 import b64encode, b64decode
from werkzeug.utils import secure_filename
from src.modules.CustomExceptions import InvalidFilenameException

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "zip"}
def validate_filename(filename:str):
    return '.' in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def transform_attachment(attach:FileStorage):
    fname = attach.filename
    if not validate_filename(fname):
        raise InvalidFilenameException("Invalid filename found!")
    else:
        sec_fname =  secure_filename(fname)
        return b64encode(sec_fname.encode() + b"|" + attach.read())

def get_attachment(attachment:bytes):
    b64dattach = b64decode(attachment)
    (fname, fle) = b64dattach.split(b"|", 1)
    return fname.decode(), b64encode(fle).decode('ascii')
