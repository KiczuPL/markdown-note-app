
import sqlite3

DATABASE = "./sqlite3.db"
NOTE_MAX_LENGTH = 10000


print("[*] Init database!")
db = sqlite3.connect(DATABASE)
sql = db.cursor()
sql.execute("DROP TABLE IF EXISTS banned_ips;")
sql.execute(
    "CREATE TABLE banned_ips (ip_address VARCHAR(16), failed_login_streak INTEGER NOT NULL, banned_until timestamp );")
sql.execute("DELETE FROM banned_ips;")
sql.execute("DROP TABLE IF EXISTS user;")
sql.execute(
    "CREATE TABLE user (username VARCHAR(32), password VARCHAR(128));")
sql.execute("DELETE FROM user;")

sql.execute("DROP TABLE IF EXISTS notes;")
sql.execute(
    f"CREATE TABLE notes (id INTEGER PRIMARY KEY, username VARCHAR(32), title VARCHAR(32), note VARCHAR({NOTE_MAX_LENGTH}), public INTEGER NOT NULL, password_hash VARCHAR(128), AES_salt VARCHAR(25), init_vector VARCHAR(25));")
sql.execute("DELETE FROM notes;")
db.commit()
