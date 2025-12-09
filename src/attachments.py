from werkzeug.datastructures.file_storage import FileStorage
from base64 import b64encode, b64decode

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}
def validate_filename(filename):
    return '.' in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def add_attachment(file:FileStorage):
    return b64encode(file.read())
