

import sqlite3
from passlib.hash import bcrypt
BCRYPT_ROUNDS = 12
FAILED_LOGIN_STREAK_BEFORE_SUSPEND = 5
DATABASE = "./sqlite3.db"
NOTE_MAX_LENGTH = 10000


print("[*] Init database!")
db = sqlite3.connect(DATABASE)
sql = db.cursor()
passwd = bcrypt.using(rounds=BCRYPT_ROUNDS).hash("123")
sql.execute("DROP TABLE IF EXISTS banned_ips;")
sql.execute(
    "CREATE TABLE banned_ips (ip_address VARCHAR(16), failed_login_streak INTEGER NOT NULL, banned_until timestamp );")
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
    f"CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), note VARCHAR({NOTE_MAX_LENGTH}), public INTEGER NOT NULL, password_hash VARCHAR(128), AES_salt VARCHAR(25), init_vector VARCHAR(25));")
sql.execute("DELETE FROM notes;")
sql.execute(
    "INSERT INTO notes (username, note, id, public, title) VALUES ('bob', 'To jest sekret!', 1, 0,'note_title');")
db.commit()
