

import sqlite3
from passlib.hash import bcrypt
BCRYPT_ROUNDS = 12
FAILED_LOGIN_STREAK_BEFORE_SUSPEND = 5
DATABASE = "./sqlite3.db"

print("[*] Init database!")
db = sqlite3.connect(DATABASE)
sql = db.cursor()
passwd = bcrypt.using(rounds=BCRYPT_ROUNDS).hash("123")
sql.execute("DROP TABLE IF EXISTS user;")
sql.execute(
    "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128), failed_login_streak INTEGER NOT NULL, suspended_until timestamp );")
sql.execute("DELETE FROM user;")
sql.execute(
    f"INSERT INTO user (username, password, failed_login_streak) VALUES ('bach', '{passwd}', 0);")
sql.execute(
    f"INSERT INTO user (username, password, failed_login_streak) VALUES ('john', '{passwd}', 0);")
sql.execute(
    f"INSERT INTO user (username, password, failed_login_streak) VALUES ('bob', '{passwd}', 0);")

sql.execute("DROP TABLE IF EXISTS notes;")
sql.execute(
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), note VARCHAR(256));")
sql.execute("DELETE FROM notes;")
sql.execute(
    "INSERT INTO notes (username, note, id) VALUES ('bob', 'To jest sekret!', 1);")
db.commit()
