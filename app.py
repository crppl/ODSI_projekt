from src.attachments import validate_filename, ALLOWED_EXTENSIONS, add_attachment
from src.usermgmt import (
    write_user,
    check_username_taken,
    login_user,
    get_users
)
from src.UserExceptions import (
    PasswordLengthException, 
    PasswordCommonException, 
    PasswordIllegalCharException, 
    PasswordLackingCharsException, 
    UsernameTakenException
)
from src.msgmgmt import (
    send_message,
    get_user_messages
)

from Cryptodome.PublicKey import RSA

import sqlite3
# import os
# from io import BytesIO

from flask import (
    Flask, 
    request, 
    redirect, 
    flash, 
    url_for, 
    render_template_string, 
    render_template, 
    send_file,
    session
)
from werkzeug.utils import secure_filename
from flask_limiter import Limiter, Limit
from flask_limiter.util import get_remote_address
from flask_session import Session
from redis import Redis

# TODO - make validating username function
# max 20 chars from a-zA-Z1-9_-
# unique
# TODO - make email address registering AND TOTP on e-mail

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

# !! For resetting users
# sql = sqlite3.connect("test.db")
# db = sql.cursor()
# db.execute("DROP TABLE IF EXISTS USERS;")
# db.execute("CREATE TABLE USERS (username NVARCHAR(20) NOT NULL, password NVARCHAR(100) NOT NULL, pubkey NVARCHAR(500) NOT NULL, privkey BLOB NOT NULL);")
# db.execute("CREATE UNIQUE INDEX userid ON USERS (username);")
# print(db.execute("SELECT * FROM USERS;").fetchall())
# db.execute('''INSERT INTO USERS (username, password, pubkey, privkey) VALUES('admin', 'gvba1234asdf5678|fghhgghhjdjdjdjd', 'abcd', 'abcd') ''')
# print(db.execute("SELECT * FROM USERS;").fetchall())
# sql.commit()
# db.close()
# sql.close()

# !! For resetting messages
# sql = sqlite3.connect("test.db")
# db = sql.cursor()
# db.execute("DROP TABLE IF EXISTS MESSAGES;")
# db.execute("CREATE TABLE MESSAGES (msgid INTEGER PRIMARY KEY AUTOINCREMENT, recievee NVARCHAR(20) NOT NULL, sendee NVARCHAR(20) NOT NULL, message_encrypted BLOB NOT NULL, encrypted_message BLOB NOT NULL);")
# db.execute("CREATE UNIQUE INDEX msgid ON MESSAGES (msgid);")
# print(db.execute("SELECT * FROM MESSAGES;").fetchall())
# sql.commit()
# db.close()
# sql.close()



# username = None
# userKeypair = None


# db = sqlite3.connect("test.db").cursor()
# print(db.execute("SELECT * FROM USERS").fetchall())
# db.close()

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    # print(session.keys())
    if 'username' not in session.keys():
        return redirect("/login")
    else:
        if request.method == 'POST':
            if request.form.get("keygen", "unknown") != "unknown":
                flash("New key pair has been generated and updated!", category="success")
                return redirect("/")

            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file')
                return redirect(request.url)
            file = request.files['file']
            # print(type(file))
            # If the user does not select a file, the browser submits an
            # empty file without a filename.
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and validate_filename(file.filename):
                filename = secure_filename(file.filename)
                # print(file.stream.read())
                # print(add_attachment(file, "admin"))
                # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return redirect(url_for('upload_file', name=filename))
        return render_template("main.html", username=session['username'])#, userkey=userKeypair.export_key().decode())


@app.route("/login", methods=["GET", "POST"])
def loginUser():
    if 'username' not in session.keys():
        if request.form.get("register") != None:
            return redirect("/register")
        else:
            if request.method == "POST":
                uname = request.form.get("unam")
                passw = request.form.get("pass")
                try:
                    if not check_username_taken(uname):
                        flash('Username not found!', category="error")
                        return redirect(request.url)
                except UsernameTakenException:
                    (login_success, pk_blob) = login_user(uname, passw)
                    if login_success:
                        session['username'] = uname
                        # print(pk_blob)
                        session['prkey'] = pk_blob
                        return redirect("/")
                    else:
                        flash('Incorrect credentials!', category="error")
                        return redirect(request.url)
                except:
                    flash('Unknown exception occured!', category="error")
                    return redirect(request.url)
            elif request.method == "GET":
                return render_template("login.html")
    else:
        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def registerUser():
    if request.method == "POST":
        ret:int
        unam = request.form.get("unam", "unknown")
        passw = request.form.get("pass", "unknown")
        if unam is None:
            flash('No username sent', category='error')
        if passw is None:
            flash('No password sent', category='error')
            return redirect(request.url)

        # user writing
        try:
            ret = write_user(unam, passw)
        except PasswordLengthException:
            flash('Password must be at least 12 characters long!', category="error")
            return redirect(request.url)
        except PasswordIllegalCharException:
            flash('Password contains illegal characters!', category="error")
            return redirect(request.url)
        except PasswordLackingCharsException as e:
            text = '''Password must contain: 
            '''
            for i in str(e).strip().split(";", 2):
                text +=  i + ", "
            text = text[:-2] + "."
            flash(text, category="error")
            return redirect(request.url)
        except PasswordCommonException:
            flash('Password is too common!', category="error")
            return redirect(request.url)
        except UsernameTakenException:
            flash('Provided username is already taken!', category="error")
            return redirect(request.url)
    
        if ret == 0:
            flash('User registered correctly! Please log in.', category="success")
            return redirect("/login")
        
        else:
            flash('Unknown error occured.', category="error")
            return redirect("/login")
        
    return render_template("register.html")


@app.route("/send", methods=["GET", "POST"])
@limiter.limit("10 per 1 minute", methods=["POST"])
def sendMessage():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        session.clear()
        return redirect("/login")

    else:
        message = request.form.get("message", "")
        if request.method == "GET":
            return render_template("send_message.html", recipients=get_users(), message=message)
        elif request.method == "POST":
            reciever = request.form.get("recSelect", "unknown")
            if message != "" and reciever != "unknown":
                send_message(session['username'], reciever, session['prkey'], message)
                flash("Message sent!", category="send_success")
                return redirect("/")
            else:
                flash("", category="error")
                return redirect(request.url)

@app.route("/messages", methods=["GET"])
@limiter.limit("10 per 1 minute", methods=["POST"])
def listMessages():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        session.clear()
        return redirect("/login")
    else:
        if request.method == "GET":
            read = []; unread = []
            for message in get_user_messages(session['username'], session['prkey']):
                if message[1]:
                    read.append(message)
                else:
                    unread.append(message)

            return render_template("messages.html", username=session['username'], unread=unread, read=read)



@app.route("/logout", methods=["POST"])
def logoutUser():
    session.clear()
    flash("Logged out successfully!", category="success")
    return redirect("/")

