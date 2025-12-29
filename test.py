from src.attachments import validate_filename, ALLOWED_EXTENSIONS, add_attachment
from src.usermgmt import write_user, check_username_taken, user_login
from src.UserExceptions import (
    PasswordLengthException, 
    PasswordCommonException, 
    PasswordIllegalCharException, 
    PasswordLackingCharsException, 
    UsernameTakenException
)

import sqlite3
import os

from flask import Flask, request, redirect, flash, url_for, render_template_string, render_template
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './files'
app.secret_key = 'wbahtaldgjhg45i791ńaFMDsl'

# sql = sqlite3.connect("test.db")
# db = sql.cursor()
# db.execute("DROP TABLE IF EXISTS USERS;")
# db.execute("CREATE TABLE USERS (username NVARCHAR(20) NOT NULL, password NVARCHAR(100) NOT NULL);")
# db.execute("CREATE UNIQUE INDEX userid ON USERS (username);")
# print(db.execute("SELECT * FROM USERS;").fetchall())
# db.execute('''INSERT INTO USERS (username, password) VALUES('admin', 'gvba1234asdf5678|fghhgghhjdjdjdjd') ''')
# print(db.execute("SELECT * FROM USERS;").fetchall())
# sql.commit()
# db.close()
# sql.close()

username = None


# db = sqlite3.connect("test.db").cursor()
# print(db.execute("SELECT * FROM USERS").fetchall())
# db.close()

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    global username
    print(username)
    if username == None:
        return redirect("/login")
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        print(type(file))
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and validate_filename(file.filename):
            filename = secure_filename(file.filename)
            # print(file.stream.read())
            print(add_attachment(file, "admin"))
            # file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('upload_file', name=filename))
    return render_template("main.html", username=username)


@app.route("/login", methods=["GET", "POST"])
def login_user():
    global username
    if username == None:
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
                    if user_login(uname, passw):
                        username = uname
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
            # flash('''Password must contain:\n- At least 2 capital letters\n- At least 2 special characters(!"#$%&'()*+,-./:;<=>?@[\]^_)\n- At least one number''', category="error")
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