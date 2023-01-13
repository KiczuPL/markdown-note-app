
from datetime import datetime, timedelta
from flask import Flask, render_template, request, make_response, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import bcrypt
import sqlite3
import bleach

from utils.validation import MINIMAL_PASSWORD_ENTROPY, verify_password, verify_password_strength, verify_username


app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"

DATABASE = "./sqlite3.db"
bleach.ALLOWED_TAGS.append(u"b")
BCRYPT_ROUNDS = 12
FAILED_LOGIN_STREAK_BEFORE_SUSPEND = 4


class User(UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    db = sqlite3.connect(
        DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    sql = db.cursor()
    sql.execute(
        f"SELECT username, password, failed_login_streak, suspended_until FROM user WHERE username = ?", (username,))
    row = sql.fetchone()
    db.close()
    try:
        username, password, failed_login_streak, suspended_until = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    user.failed_login_streak = failed_login_streak
    user.suspended_until = suspended_until
    return user


def suspend_user(username):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    suspend_until = datetime.now()+timedelta(0, 600)
    sql.execute(
        "UPDATE user SET suspended_until = ? WHERE username = ?", (suspend_until,  username,))
    db.commit()
    db.close()


def pardon_user(username):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        "UPDATE user SET suspended_until=? WHERE username=?", (None,  username,))
    db.commit()
    db.close()


def update_user_failed_login_streak(username, streak):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        "UPDATE user SET failed_login_streak=? WHERE username=?", (streak, username))
    db.commit()
    db.close()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = str(request.form.get("username"))
        password = str(request.form.get("password"))
        user = user_loader(username)

        if user is None:
            flash("Wrong username or password")
            return render_template("index.html")

        if user.suspended_until:
            if (user.suspended_until > datetime.now()):
                pardon_user(user.id)
            else:
                flash("Your account is suspended, come back in 10 minutes")
                return render_template("index.html")

        if bcrypt.verify(password, user.password):
            login_user(user)
            if (user.failed_login_streak > 0):
                update_user_failed_login_streak(username, 0)

            return redirect('/hello')
        else:
            flash("Wrong username or password")
            update_user_failed_login_streak(
                user.id, user.failed_login_streak + 1)
            if (user.failed_login_streak > FAILED_LOGIN_STREAK_BEFORE_SUSPEND):
                suspend_user(username)
                flash("Your account got suspended for next 10 minutes")

            return render_template("index.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")


@app.route("/hello", methods=['GET'])
@login_required
def hello():
    if request.method == 'GET':
        username = current_user.id

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id FROM notes WHERE username == ?", (username,))
        notes = sql.fetchall()
        db.close()
        return render_template("hello.html", username=username, notes=notes)


@app.route("/render", methods=['POST'])
@login_required
def render():
    md = request.form.get("markdown", "")
    cleaned = bleach.clean(md)
    rendered = markdown.markdown(md)
    username = current_user.id
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        f"INSERT INTO notes (username, note) VALUES (?, ?)", (username, rendered))
    db.commit()
    db.close()
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
        db.close()
        if username != current_user.id:
            return "Access to note forbidden", 403
        return render_template("markdown.html", rendered=rendered)
    except:
        db.close()
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
            flash(
                'Your password should have 10-128 characters, numbers and special signs')
            is_valid = False
        [password_too_weak, entropy] = verify_password_strength(password)
        if password_too_weak:
            flash(
                f'Password has too low entropy, required entropy: {MINIMAL_PASSWORD_ENTROPY}, your entropy: {entropy}.')
            is_valid = False
        if not verify_username(username):
            flash('Your username should have 3-20 alphanumeric characters.')
            is_valid = False
        if user_loader(username):
            flash('Username already taken.')
            is_valid = False
        if not is_valid:
            return render_template("register.html")
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"INSERT INTO user (username, password, failed_login_streak) VALUES (?, ?, ?);",
                    (username, bcrypt.using(round=BCRYPT_ROUNDS).hash(password), 0))

        db.commit()
        db.close()
        return redirect('/')


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    passwd = bcrypt.using(rounds=BCRYPT_ROUNDS).hash("123")
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute(
        "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128), failed_login_streak INTEGER NOT NULL, suspended_until timestamp );")
    sql.execute("DELETE FROM user;")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bach', '{passwd}', 0);")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('john', '{passwd}', 0);")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bob', '{passwd}', 0);")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute(
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256));")
    sql.execute("DELETE FROM notes;")
    sql.execute(
        "INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
    db.commit()

    app.run("0.0.0.0", 5000, debug=True)
