
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import markdown
from passlib.hash import bcrypt
import sqlite3
import bleach
from utils.encryption import decrypt_note, encrypt_note

from utils.validation import MINIMAL_PASSWORD_ENTROPY, verify_note_content, verify_note_title, verify_password, verify_password_strength, verify_username

from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)


app.wsgi_app = ProxyFix(app.wsgi_app)

login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = "206363ef77d567cc511df5098695d2b85058952afd5e2b1eecd5aed981805e60"


DATABASE = "./sqlite3.db"
NOTE_MAX_LENGTH = 10000
bleach.ALLOWED_TAGS = []
BCRYPT_ROUNDS = 12
FAILED_LOGIN_STREAK_BEFORE_SUSPEND = 4
FAILED_LOGIN_STREAK_BAN_TIME_IN_SECONDS = 600


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
        f"SELECT username, password FROM user WHERE username = ?", (username,))
    row = sql.fetchone()
    db.close()
    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user


def suspend_ip_address(ip_address):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    suspend_until = datetime.now()+timedelta(0, FAILED_LOGIN_STREAK_BAN_TIME_IN_SECONDS)
    sql.execute("UPDATE banned_ips SET banned_until=? WHERE ip_address=?",
                (suspend_until, ip_address,))
    db.commit()
    db.close()


def is_ip_address_suspended(ip_address):
    db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
    sql = db.cursor()
    sql.execute(
        "SELECT banned_until FROM banned_ips WHERE ip_address=?", (ip_address,))

    try:
        banned_until, = sql.fetchone()
        if banned_until < datetime.now():
            pardon_ip_address(ip_address)
            return False
        return True
    except:
        return False


def pardon_ip_address(ip_address):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute("DELETE FROM banned_ips WHERE ip_address=?", (ip_address,))
    db.commit()
    db.close()


def increase_ip_address_failed_login_streak(ip_address):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()

    sql.execute(
        "SELECT failed_login_streak FROM banned_ips WHERE ip_address=?", (ip_address,))
    try:
        streak, = sql.fetchone()
        if streak > FAILED_LOGIN_STREAK_BEFORE_SUSPEND:
            suspend_ip_address(ip_address)
        sql.execute(
            "UPDATE banned_ips SET failed_login_streak=? WHERE ip_address=?", (streak+1, ip_address,))

    except:
        streak = 1
        sql.execute(
            "INSERT INTO banned_ips (ip_address, failed_login_streak) VALUES (?, ?)", (ip_address, streak,))
    db.commit()
    db.close()
    return streak+1 > FAILED_LOGIN_STREAK_BEFORE_SUSPEND


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


@ app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("index.html")
    if request.method == "POST":
        username = str(request.form.get("username"))
        password = str(request.form.get("password"))
        sender_ip = request.host
        user = user_loader(username)

        #print("HOST-----------> ", request.host)
        #print("remote_addr----> ", sender_ip)
        #print("ENVIRON-------->", request.environ['REMOTE_ADDR'])
        # print("X-FORWARDED----> ",
        #      request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr))
        if user is None:
            flash("Wrong username or password")
            return render_template("index.html")

        if is_ip_address_suspended(sender_ip):
            flash("Your ip address is suspended, come back in 10 minutes")
            return render_template("index.html")

        if bcrypt.verify(password, user.password):
            login_user(user)
            return redirect('/hello')
        else:
            flash("Wrong username or password")
            if increase_ip_address_failed_login_streak(sender_ip):
                flash("Your ip address got suspended for next 10 minutes")

            return render_template("index.html")


@ app.route("/logout",  methods=["POST"])
@ login_required
def logout():
    logout_user()
    return redirect("/")


@ app.route("/hello", methods=['GET'])
@ login_required
def hello():
    if request.method == 'GET':
        return render_template("hello.html", username=current_user.id, notes=get_user_notes(current_user.id))


def get_user_notes(username):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(
        "SELECT id, username, title FROM notes WHERE username == ? OR public=1", (username,))
    notes = sql.fetchall()
    # print(notes)
    db.close()
    return notes


@ app.route("/render", methods=['POST'])
@ login_required
def render():
    md = str(request.form.get("markdown", ""))
    title = request.form.get("title")
    public = request.form.get("public")
    encrypt = request.form.get("encrypt")
    encryption_password = str(request.form.get("password"))
    flags_invalid = False

    # print([md, public, encrypt, encryption_password])
    if title is None or title == "" or title.isspace():
        flash("Your note needs a title")
        return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)
    if not verify_note_title(title):
        flash("Title can contain 1-25 alphanumeric characters and special signs")
        return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)
    [is_note_valid, note_valid_messages] = verify_note_content(md)
    if not is_note_valid:
        for msg in note_valid_messages:
            flash(msg)
        return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)

    if public == None:
        public = False
    elif public == 'on':
        public = True
    else:
        flags_invalid = True
    if encrypt == None:
        encrypt = False
    elif encrypt == 'on':
        encrypt = True
    else:
        flags_invalid = True

    if flags_invalid:
        flash("Something is wrong in render request")
        return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)

    if encrypt and public:
        flash("Encrypted notes cannot be public")
        return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)

    if encrypt:
        if not verify_password(encryption_password):
            flash(
                'Your password should have 10-128 characters, numbers and special signs')
            return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)
        [password_too_weak, entropy] = verify_password_strength(
            encryption_password)
        if password_too_weak:
            flash(
                f'Password has too low entropy, required entropy: {MINIMAL_PASSWORD_ENTROPY}, your entropy: {entropy}.')
            return render_template("hello.html", username=current_user.id, raw_note=md, notes=get_user_notes(current_user.id), title=title)

        cleaned = bleach.clean(md)
        rendered = markdown.markdown(cleaned)
        username = current_user.id

        [encrypted, salt, init_vector] = encrypt_note(
            rendered, encryption_password)
        encryption_password_hash = bcrypt.using(
            rounds=BCRYPT_ROUNDS).hash(encryption_password)
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(
            f"INSERT INTO notes (username, title, note, public, password_hash, AES_salt, init_vector) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, title, encrypted, public, encryption_password_hash, salt, init_vector))
        db.commit()
        db.close()
        # print("SSSSS")
        return render_template("markdown.html", rendered=rendered)

    else:
        # print("ASSAS")
        cleaned = bleach.clean(md)
        rendered = markdown.markdown(cleaned)
        username = current_user.id
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(
            f"INSERT INTO notes (username, title, note, public) VALUES (?, ?, ?, ?)", (username, title, rendered, public))
        db.commit()
        db.close()
        return render_template("markdown.html", rendered=rendered)


# get to note, will redirect to proper link if note is encrypted or not
@ app.route("/note/<rendered_id>", methods=['GET'])
@ login_required
def get_note(rendered_id):
    if request.method == "GET":
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(
            "SELECT id, username, public, password_hash FROM notes WHERE id == ?", (rendered_id,))

        try:
            note_id, username,  public, password_hash = sql.fetchone()
            db.close()
            if username != current_user.id and not public:
                return "Access to note forbidden", 403

            if password_hash:
                return redirect(f"/note/encrypted/{note_id}")
            return redirect(f"/note/unencrypted/{note_id}")
        except:
            db.close()
            return "Note not found", 404


@ app.route("/note/<rendered_id>/delete", methods=['POST'])
@ login_required
def delete_note(rendered_id):
    if request.method == "POST":
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(
            "SELECT id, username FROM notes WHERE id == ?", (rendered_id,))

        try:
            note_id, username, = sql.fetchone()

            if username != current_user.id:
                db.close()
                return "Access to note forbidden", 403

            sql.execute(
                "DELETE FROM notes WHERE id == ?", (note_id,))

            db.commit()
            db.close()
            return redirect("/hello")
        except:
            db.close()
            return "Note not found", 404


@ app.route("/note/unencrypted/<rendered_id>")
@ login_required
def render_unencrypted(rendered_id):
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    sql.execute(f"SELECT username, note, public, password_hash FROM notes WHERE id == ?",
                (rendered_id,))

    try:
        username, note, public, password_hash = sql.fetchone()
        db.close()
        if (password_hash):
            return "Access to note forbidden", 403
        if username != current_user.id and not public:
            return "Access to note forbidden", 403

        return render_template("markdown.html", rendered=note)
    except:
        db.close()
        return "Note not found", 404


@ app.route("/note/encrypted/<rendered_id>", methods=['GET', 'POST'])
@ login_required
def render_encrypted(rendered_id):
    if request.method == 'GET':
        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id, username, password_hash FROM notes WHERE id == ?",
                    (rendered_id,))

        try:
            id, username, password_hash = sql.fetchone()
            db.close()
            if not password_hash:
                return "Access to note forbidden", 403
            if username != current_user.id:
                return "Access to note forbidden", 403

            return render_template("decipher.html", id=id)
        except:
            db.close()
            return "Note not found", 404

    if request.method == 'POST':
        password = str(request.form.get("password"))
        if password is None or not verify_password(password):
            flash("Wrong password")
            return render_template("decipher.html", id=id)

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT id, username, note, password_hash, AES_salt, init_vector  FROM notes WHERE id == ?",
                    (rendered_id,))

        try:
            id, username, note, password_hash, salt, init_vector = sql.fetchone()
            db.close()
            if username != current_user.id:
                return "Access to note forbidden", 403
            if (bcrypt.verify(password, password_hash)):
                decrypted_note = decrypt_note(
                    note, password, salt, init_vector)
                return render_template("markdown.html", rendered=decrypted_note)
            else:
                flash("Wrong password")
                return render_template("decipher.html", id=id)
        except:
            db.close()
            return "Note not found", 404


@ app.route("/user/register", methods=['GET', 'POST'])
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


@ app.route("/user/passwd", methods=['GET', 'POST'])
@ login_required
def change_password():
    if request.method == "GET":
        return render_template("passwd.html")
    if request.method == "POST":
        password = str(request.form.get("password_old"))
        password_new = str(request.form.get("password_new"))
        password_retyped = str(request.form.get("password_retyped"))

        db = sqlite3.connect(
            DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        sql = db.cursor()
        sql.execute(
            f"SELECT password FROM user WHERE username = ?", (current_user.id,))
        password_hash, = sql.fetchone()

        if bcrypt.verify(password, password_hash):
            is_valid = True
            if not verify_password(password_new):
                flash(
                    'Your password should have 10-128 characters, numbers and special signs')
                is_valid = False
            [password_too_weak, entropy] = verify_password_strength(
                password_new)

            if password_too_weak:
                flash(
                    f'Password has too low entropy, required entropy: {MINIMAL_PASSWORD_ENTROPY}, your entropy: {entropy}.')
                is_valid = False
            if password_new != password_retyped:
                flash("Retyped password is different than new password.")
                is_valid = False
            if not is_valid:
                return render_template("passwd.html")

            sql.execute(
                "UPDATE user SET password=? WHERE username=?", (bcrypt.using(rounds=BCRYPT_ROUNDS).hash(password_new), current_user.id,))
            db.commit()
            db.close()
            return redirect("/hello")
        else:
            db.close()
            flash("Wrong password.")
            return render_template("passwd.html")


if __name__ == "__main__":
    print("[*] Init database!")
    db = sqlite3.connect(DATABASE)
    sql = db.cursor()
    passwd = bcrypt.using(rounds=BCRYPT_ROUNDS).hash("123")
    sql.execute("DROP TABLE IF EXISTS banned_ips;")
    sql.execute(
        "CREATE TABLE banned_ips (ip_address VARCHAR(16), failed_login_streak INTEGER NOT NULL, banned_until timestamp );")
    sql.execute("DROP TABLE IF EXISTS user;")
    sql.execute(
        "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128);")
    sql.execute("DELETE FROM user;")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bach', '{passwd}');")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('john', '{passwd}');")
    sql.execute(
        f"INSERT INTO user (username, password) VALUES ('bob', '{passwd}');")

    sql.execute("DROP TABLE IF EXISTS notes;")
    sql.execute(
        f"CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), note VARCHAR({NOTE_MAX_LENGTH}), public INTEGER NOT NULL, password_hash VARCHAR(128), AES_salt VARCHAR(25), init_vector VARCHAR(25));")
    sql.execute("DELETE FROM notes;")
    sql.execute(
        "INSERT INTO notes (username, note, id, public, title) VALUES ('bob', 'To jest sekret!', 1, 0,'note_title');")
    db.commit()

    app.run("0.0.0.0", 5000, debug=True)
