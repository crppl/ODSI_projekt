from src import app
from src.modules.attachments import validate_filename, ALLOWED_EXTENSIONS
from src.modules.usermgmt import (
    write_user,
    check_username_taken,
    login_user,
    get_users
)
from src.modules.CustomExceptions import (
    PasswordLengthException, 
    PasswordCommonException, 
    PasswordIllegalCharException, 
    PasswordLackingCharsException, 
    UsernameTakenException
)
from src.modules.msgmgmt import (
    send_message,
    get_user_messages,
    check_message_recipient,
    delete_message,
    get_user_message_id,
    mark_message_as_read
)

from Cryptodome.PublicKey import RSA
from io import BytesIO
from base64 import b64decode, b64encode
import bleach
import time
import pyotp
import qrcode

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

from src import app, limiter

# TODO - make validating username function
# max 20 chars from a-zA-Z1-9_-
# unique
# TODO - make TOTP


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
        return redirect("/login")
    else:
        if request.method == 'POST':
            if request.form.get("keygen", "unknown") != "unknown":
                flash("New key pair has been generated and updated!", category="success")
                return redirect("/")
        elif request.method == "GET":
            return render_template("main.html")



@app.route("/login", methods=["GET", "POST"])
def loginUser():
    if "secret_otp" in session.keys():
        session.pop("secret_opt")
    if "qr_code" in session.keys():
        session.pop("qr_code")
    if 'username' not in session.keys() or 'totp_authenticated' not in session.keys():
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
                    (login_success, pk_blob, secret) = login_user(uname, passw)
                    if login_success:
                        session['username'] = uname
                        session['prkey'] = pk_blob
                        session['secret_otp'] = secret
                        elapsed = time.time() - begin
                        if elapsed < 3:
                            time.sleep(3-elapsed)
                        return redirect("/2fa")
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

@app.route("/2fa", methods=["GET", "POST"])
def twoFactorAuth():
    if 'username' not in session.keys() or 'prkey' not in session.keys() or 'secret_otp' not in session.keys():
        return redirect("/login")
    else:
        if request.method == "GET":
            return render_template("2fa.html")
        elif request.method == "POST":        
            begin = time.time()
            totp = pyotp.TOTP(session['secret_otp'])
            session['TOTP'] = bleach.clean(request.form.get("totp_val", "unknown"))
            if session['TOTP'] == "unknown":
                elapsed = time.time() - begin
                if elapsed < 2:
                    time.sleep(2 - elapsed)
                return redirect("/logout")
            else:
                if totp.verify(session['TOTP']):
                    session['totp_authenticated'] = True
                    session.pop('TOTP')
                    session.pop('secret_otp')
                    del totp
                    elapsed = time.time() - begin
                    if elapsed < 2:
                        time.sleep(2 - elapsed)
                    flash('Logged in successfully!', category="login_success")
                    return redirect ("/")
                else:
                    elapsed = time.time() - begin
                    if elapsed < 2:
                        time.sleep(2 - elapsed)
                    flash("Incorrect code.", category="2fa_error")
                    return redirect(request.url)
        else:
            return redirect("/logout")


@app.route("/logout", methods=["GET", "POST"])
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
            (ret, session['secret_otp']) = write_user(session['unam'], session['passw'])
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
            flash('User registered correctly!', category="success")
            return redirect("/registration_qr")
        
        else:
            flash('Unknown error occured.', category="error")
            elapsed = time.time() - begin
            if elapsed < 3:
                time.sleep(3-elapsed)
            return redirect("/login")
        
    return render_template("register.html")


@app.route("/registration_qr", methods=["GET", "POST"])
def registrationQR():
    if "secret_otp" not in session.keys():
        if request.method == "GET":
            uri = pyotp.totp.TOTP(session['secret_otp']).provisioning_uri(name=session['unam'], issuer_name="ODSI_APP")
            qr_code = qrcode.QRCode()
            qr_code.add_data(uri)
            qr_image = qr_code.make_image()
            buf = BytesIO()
            qr_image.save(buf, format="PNG")
            session['qr_code'] = b64encode(buf.getvalue()).decode()
            return render_template("qr_onetime.html")
        # elif request.method == "POST":
        else:
            return redirect("/logout")
        
    else:
        return redirect("/logout")



@app.route("/gen_keypair", methods=["GET", "POST"])
def generateKeypairMain():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
        return redirect("/logout")
    else:
        if request.method == "GET":
            return render_template("generate_keypair.html")
        elif request.method == "POST":
            begin = time.time()
            session['keygen_req'] = bleach.clean(request.form.get("keygen", "unknown"))
            if session['keygen_req'] == "unknown":
                session.pop('keygen_req')
                flash("Keygen generation aborted.", category="keygen_error")
                return redirect("/")
            elif session['keygen_req'] == "keygen":
                flash("Functionality not completed :(", category="keygen_error")
                return redirect("/")
            else:
                flash("Keygen generation aborted.", category="keygen_error")
                return redirect("/")




@app.route("/send", methods=["GET", "POST"])
@limiter.limit("10 per 1 minute", methods=["POST"])
def sendMessageApp():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
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
                    ret = send_message(session['title'], session['username'], session.pop('reciever'), session['prkey'], session.pop('message'), attachments=session.pop('attached_file'))
                except Exception as e:
                    print("EXCEPTION!!!!", e)
                    elapsed = time.time() - begin
                    if elapsed < 1.2:
                        time.sleep(1.2 - elapsed)
                    flash('There was an unexpected error. Message not sent.', category="send_error")
                    return redirect("/")
                elapsed = time.time() - begin
                if elapsed < 1.2:
                    time.sleep(1.2 - elapsed)
                if ret:
                    flash("Message sent!", category="send_success")
                    return redirect("/")
                else:
                    flash("Error occured while sending message.", "send_error")
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
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
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
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
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
            else:
                flash("Action failed.", category="action_error")
                return redirect(request.url)
        elif session["msg_action"] == "Mark As Read":
            if check_message_recipient(session['username'], session['msge_id']):
                if mark_message_as_read(session['msge_id'], session['prkey']):
                    refresh_user_messages()
                    flash('Message successfully marked as read.', category="maread_success")
                    return redirect("/messages")
                else:
                    flash('Message marking failed.', category="maread_error")
                    return redirect("/messages")
            else:
                flash("Action failed.", category="action_error")
                return redirect(request.url)

@app.route("/message_details", methods=["GET", "POST"])
def ListSpecificMessage():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True: 
        return redirect("/logout")
    elif check_message_recipient(session['username'], session['chosen_message'][0]):
        return render_template("message.html")
    else:
        return render_template("not_your_message.html")


@app.route("/not_your_message", methods=["GET"])
def func_not_your_message():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True: 
        return redirect("/logout")
    else:
        return render_template("not_your_message.html")



@app.route("/download_attachments", methods=["GET"])
def download_attachment():
    if 'username' not in session.keys() or 'prkey' not in session.keys()  \
        or 'totp_authenticated' not in session.keys() or session['totp_authenticated'] != True:
        return redirect("/logout")
    else:
        if session['chosen_message'][7] is None or session['chosen_message'][7] == "":
            return redirect(request.url)
        return send_file(BytesIO(b64decode(session['chosen_message'][8])), download_name=session['chosen_message'][7], as_attachment=True)
    


def refresh_user_messages():
    read = []; unread = []
    temp = get_user_messages(session['username'], session['prkey'])
    if temp:
        for message in temp:
            if message != False:
                if message[5]:
                    read.append(message)
                else:
                    unread.append(message)
            session['read_msgs'] = read; session['unread_msgs'] = unread
        else:
            pass
    else:
        flash('Unknown error occured', "refresh_error")
        return redirect("/")


    
# import sqlite3
# from src.modules.usermgmt import connect_to_db
# !! For resetting users
# sql, db = connect_to_db()
# db.execute("DROP TABLE IF EXISTS USERS;")
# db.execute("CREATE TABLE USERS (username NVARCHAR(20) NOT NULL, password NVARCHAR(100) NOT NULL, pubkey NVARCHAR(500) NOT NULL, privkey BLOB NOT NULL, secret BLOB NOT NULL);")
# db.execute("CREATE UNIQUE INDEX userid ON USERS (username);")
# print(db.execute("SELECT * FROM USERS;").fetchall())
# sql.commit()
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