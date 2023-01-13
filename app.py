
from flask import Flask, render_template, request, make_response, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from collections import deque
import markdown
from passlib.hash import bcrypt
import sqlite3
import bleach

from utils.validation import verify_password, verify_username


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"
bcrypt.rounds = 128
bleach.ALLOWED_TAGS.append(u"b")


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        f"SELECT username, password FROM user WHERE username = ?", (username,))
    row = sql.fetchone()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


recent_users = deque(maxlen=3)


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = str(request.form.get("username"))
        password = str(request.form.get("password"))
        user = user_loader(username)

        if user is None:
            return "Nieprawidłowy login lub hasło", 401

        if bcrypt.verify(password, user.password):
            login_user(user)
            return redirect('/hello')
        else:
            return "Nieprawidłowy login lub hasło", 401


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        print(current_user.id)
        username = current_user.id

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id FROM notes WHERE username == ?", (username,))
        notes = sql.fetchall()

        return render_template("hello.html", username=username, notes=notes)


@app.route("/render", methods=['POST'])
@login_required
def render():
    md = request.form.get("markdown", "")
    cleaned = bleach.clean(md)
    rendered = markdown.markdown(md)
    print(cleaned)
    print(rendered)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        f"INSERT INTO notes (username, note) VALUES (?, ?)", (username, rendered))
    db.commit()
    return render_template("markdown.html", rendered=rendered)


@app.route("/render/<rendered_id>")
@login_required
def render_old(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, note FROM notes WHERE id == ?",
                (rendered_id,))

    try:
        username, rendered = sql.fetchone()
        if username != current_user.id:
            return "Access to note forbidden", 403
        return render_template("markdown.html", rendered=rendered)
    except:
        return "Note not found", 404


@app.route("/user/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    if request.method == 'POST':
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        is_valid = True

        if not verify_password(password):
            flash('Your password should have 8-128 characters, at least one uppercase letter, one lowercase letter, one number and one special character')
            is_valid = False
        if not verify_username(username):
            flash('Your username should have 5-20 alphanumeric characters')
            is_valid = False
        if user_loader(username):
            flash('Username already taken.')
            is_valid = False
        if not is_valid:
            return render_template("register.html")

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"INSERT INTO user (username, password) VALUES (?, ?);",
                    (username, bcrypt.hash(password),))

        db.commit()

        return redirect('/')


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    passwd = bcrypt.hash("123")
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute(
        "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
    sql.execute("DELETE FROM user;")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bach', '{passwd}');")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('john', '{passwd}');")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bob', '{passwd}');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256));")
    sql.execute("DELETE FROM notes;")
    sql.execute(
        "INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()

    app.run("0.0.0.0", 5000, debug=True)
