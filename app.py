from src.attachments import validate_filename, ALLOWED_EXTENSIONS
from src.usermgmt import (
    write_user,
    check_username_taken,
    login_user,
    get_users
)
from src.CustomExceptions import (
    PasswordLengthException, 
    PasswordCommonException, 
    PasswordIllegalCharException, 
    PasswordLackingCharsException, 
    UsernameTakenException
)
from src.msgmgmt import (
    send_message,
    get_user_messages,
    check_message_recipient,
    delete_message,
    get_user_message_id,
    mark_message_as_read
)

from Cryptodome.PublicKey import RSA
from io import BytesIO
from base64 import b64decode
from flask_limiter import Limiter, Limit
from flask_limiter.util import get_remote_address
from flask_session import Session
import bleach
import time

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

# import sqlite3
# # !! For resetting users
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

# # !! For resetting messages
# sql = sqlite3.connect("test.db")
# db = sql.cursor()
# db.execute("DROP TABLE IF EXISTS MESSAGES;")
# db.execute("CREATE TABLE MESSAGES (msgid INTEGER PRIMARY KEY AUTOINCREMENT, recievee NVARCHAR(20) NOT NULL, sendee NVARCHAR(20) NOT NULL, message_encrypted BLOB NOT NULL, encrypted_message BLOB NOT NULL);")
# db.execute("CREATE UNIQUE INDEX msgid ON MESSAGES (msgid);")
# print(db.execute("SELECT * FROM MESSAGES;").fetchall())
# sql.commit()
# db.close()
# sql.close()


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        return redirect("/login")
    else:
        if request.method == 'POST':
            if request.form.get("keygen", "unknown") != "unknown":
                flash("New key pair has been generated and updated!", category="success")
                return redirect("/")
        elif request.method == "GET":
            return render_template("main.html")
            # check if the post request has the file part
            # if 'file' not in request.files:
            #     flash('No file')
            #     return redirect(request.url)
            # fileg = request.files['file']
            # # print(type(file))
            # # If the user does not select a file, the browser submits an
            # # empty file without a filename.
            # if fileg.filename == '':
            #     flash('No selected file')
            #     return redirect(request.url)
            # if fileg and validate_filename(fileg.filename):
            #     filename = secure_filename(fileg.filename)
            #     print(filename, type(filename))
            #     retvals = fileg.stream.read()
            #     print(retvals)
            #     retfiole = BytesIO(retvals)
            #     print(type(retfiole))
            #     # print(file.stream.read())
            #     # print(add_attachment(file, "admin"))
            #     # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            #     return send_file(retfiole, download_name=filename, as_attachment=True)
            #     return redirect(url_for('upload_file', name=filename))



@app.route("/login", methods=["GET", "POST"])
def loginUser():
    if 'username' not in session.keys():
        if request.form.get("register", "unknown") != "unknown":
            return redirect("/register")
        else:
            if request.method == "POST":
                begin = time.time()
                uname = bleach.clean(request.form.get("unam"))
                passw = bleach.clean(request.form.get("pass"))
                try:
                    if not check_username_taken(uname):
                        flash('Username not found!', category="error")
                        elapsed = time.time() - begin
                        if elapsed < 3:
                            time.sleep(3-elapsed)
                        return redirect(request.url)
                except UsernameTakenException:
                    (login_success, pk_blob) = login_user(uname, passw)
                    if login_success:
                        session['username'] = uname
                        session['prkey'] = pk_blob
                        elapsed = time.time() - begin
                        if elapsed < 3:
                            time.sleep(3-elapsed)
                        return redirect("/")
                    else:
                        elapsed = time.time() - begin
                        if elapsed < 3:
                            time.sleep(3-elapsed)
                        flash('Incorrect credentials!', category="error")
                        return redirect(request.url)
                except:
                    elapsed = time.time() - begin
                    if elapsed < 4:
                        time.sleep(4-elapsed)
                    flash('Unknown exception occured!', category="error")
                    return redirect(request.url)
            elif request.method == "GET":
                return render_template("login.html")
    else:
        time.sleep(1)
        return redirect("/")


@app.route("/logout", methods=["POST"])
def logoutUser():
    session.clear()
    flash("Logged out!", category="success")
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def registerUser():
    if request.method == "POST":
        begin = time.time()
        ret:int
        session['unam'] = bleach.clean(request.form.get("unam", "unknown"))
        session['passw'] = bleach.clean(request.form.get("pass", "unknown"))
        if session['unam'] is None or session['unam'] == "unknown":
            flash('No username sent', category='error')
        if session['passw'] is None or session['passw'] == "unknown":
            flash('No password sent', category='error')
            return redirect(request.url)

        # user writing
        try:
            ret = write_user(session['unam'], session['passw'])
        except PasswordLengthException:
            flash('Password must be at least 12 characters long!', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect(request.url)
        except PasswordIllegalCharException:
            flash('Password contains illegal characters!', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect(request.url)
        except PasswordLackingCharsException as e:
            text = '''Password must contain: 
            '''
            for i in str(e).strip().split(";", 2):
                text +=  i + ", "
            text = text[:-2] + "."
            flash(text, category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect(request.url)
        except PasswordCommonException:
            flash('Password is too common!', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect(request.url)
        except UsernameTakenException:
            flash('Provided username is already taken!', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect(request.url)
        if ret == 0:
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            flash('User registered correctly! Please log in.', category="success")
            return redirect("/login")
        
        else:
            flash('Unknown error occured.', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect("/login")
        
    return render_template("register.html")




@app.route("/send", methods=["GET", "POST"])
@limiter.limit("10 per 1 minute", methods=["POST"])
def sendMessageApp():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        return redirect("/logout")
    else:
        if request.method == "GET":
            return render_template("send_message.html", recipients=get_users())
        elif request.method == "POST":
            begin = time.time()
            session['title'] = bleach.clean(request.form.get("message_title", "unknown"))
            session['message'] = bleach.clean(request.form.get("message", ""))
            session['reciever'] = bleach.clean(request.form.get("recSelect", "unknown"))
            session['attached_file'] = request.files["send_attachment"]
            if session['attached_file'].filename != "" and not validate_filename(session['attached_file'].filename):
                session.pop('attached_file')
                elapsed = time.time() - begin
                if elapsed < 1.2:
                    time.sleep(1.2 - elapsed)
                flash("Unsupported file name/extension!", category="send_error")
                return redirect(request.url)
            elif session['message'] != "" and session['reciever'] != "unknown":
                try:
                    send_message(session['title'], session['username'], session.pop('reciever'), session['prkey'], session.pop('message'), attachments=session.pop('attached_file'))
                except Exception as e:
                    print("EXCEPTION!!!!", e)
                    elapsed = time.time() - begin
                    if elapsed < 1.2:
                        time.sleep(1.2 - elapsed)
                    flash('There was an unexpected error. Message not sent.', category="send_error")
                    return redirect("/")
                flash("Message sent!", category="send_success")
                elapsed = time.time() - begin
                if elapsed < 1.2:
                    time.sleep(1.2 - elapsed)
                return redirect("/")
            else:
                elapsed = time.time() - begin
                if elapsed < 1.2:
                    time.sleep(1.2 - elapsed)
                flash("Unknown error occured", category="error")
                return redirect(request.url)




@app.route("/messages", methods=["GET"])
@limiter.limit("10 per 1 minute", methods=["POST"])
def listMessages():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        return redirect("/logout")
    else:
        begin = time.time()
        if 'chosen_message' in session.keys():
            session.pop('chosen_message')
        if request.method == "GET":
            # if "read_msgs" not in session.keys() or "unread_msgs" not in session.keys():
            refresh_user_messages()
            elapsed = time.time() - begin
            if elapsed < 1.2:
                time.sleep(1.2 - elapsed)
            return render_template("messages.html")



@app.route("/manage_msg", methods=["POST"])
def delete_message_app():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        return redirect("/logout")
    else:
        session["msge_id"] = bleach.clean(request.form.get("msg_id", "unknown"))
        session["msg_action"] = bleach.clean(request.form.get("msgAction", "unknown"))
        if session["msg_action"] == "unknown":
            return redirect("/messages")
        elif session["msg_action"] == "Details":
            if check_message_recipient(session['username'], session['msge_id']):
                try:
                    session['chosen_message'] = get_user_message_id(session['msge_id'], session['prkey'])
                # flash("WARNING! This message does not match the original signature!\nIt may have been tampered with!", category="invalid_sign")
                except:
                    return redirect("/not_your_message")
    
                return redirect("/message_details")
            else:
                return redirect("/not_your_message")
        elif session["msg_action"] == "Delete":
            if check_message_recipient(session['username'], session['msge_id']):
                delete_message(session['msge_id'])
                refresh_user_messages()
                flash('Message deleted succesfully.', category="delete_success")
                return redirect("/messages")
        elif session["msg_action"] == "Mark As Read":
            if check_message_recipient(session['username'], session['msge_id']):
                mark_message_as_read(session['msge_id'], session['prkey'])
                refresh_user_messages()
                flash('Message successfully marked as read.', category="maread_success")
                return redirect("/messages")


@app.route("/message_details", methods=["GET", "POST"])
def ListSpecificMessage():
    if 'username' not in session.keys() or 'prkey' not in session.keys(): 
        return redirect("/logout")
    elif check_message_recipient(session['username'], session['chosen_message'][0]):
        return render_template("message.html")
    else:
        return render_template("not_your_message.html")


@app.route("/not_your_message", methods=["GET"])
def func_not_your_message():
    if 'username' not in session.keys() or 'prkey' not in session.keys(): 
        return redirect("/logout")
    else:
        return render_template("not_your_message.html")



@app.route("/download_attachments", methods=["GET"])
def download_attachment():
    if 'username' not in session.keys() or 'prkey' not in session.keys():
        return redirect("/logout")
    else:
        if session['chosen_message'][7] is None or session['chosen_message'][7] == "":
            return redirect(request.url)
        return send_file(BytesIO(b64decode(session['chosen_message'][8])), download_name=session['chosen_message'][7], as_attachment=True)
    


def refresh_user_messages():
    read = []; unread = []
    for message in get_user_messages(session['username'], session['prkey']):
        if message[5]:
            read.append(message)
        else:
            unread.append(message)
    session['read_msgs'] = read; session['unread_msgs'] = unread