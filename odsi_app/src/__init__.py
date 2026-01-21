from flask import Flask
from flask_limiter import Limiter, Limit
from flask_limiter.util import get_remote_address
from flask_session import Session

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './files'
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_TYPE='filesystem',
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True
    )

app.secret_key = 'wbahtaldgjhg45i791ńaFMDsl'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[
        Limit("5/90second", methods=["POST"])
        ],
    strategy="fixed-window"
)

Session(app)

from src import app_code