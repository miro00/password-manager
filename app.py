import sqlite3
import os
import hashlib

db = sqlite3.connect("Database.db")
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
  username text, 
  password_hash text, 
  password_salt text
  )
""")
user_id = input("Введите имя пользователя (Нажмите 1 чтобы создать нового) ")


def password_hash(p):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        p.encode('utf-8'),
        salt,
        100000
    )
    password_storage = salt + key
    return password_storage

def password_check(p, key, salt):
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        p.encode('utf-8'),
        salt,
        100000
    )
    if new_key == key:
        return True
    else:
        return False

if "1" in user_id:
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")

    storage = password_hash(password)

    cursor.executemany("INSERT INTO users (username, password_hash, password_salt) VALUES (?,?,?)",
                       [(username, storage[32:], storage[:32])])
    db.commit()
else:
    cursor.execute("SELECT * FROM users WHERE username=?", [user_id])
    if not cursor.fetchall():
        print('Пользователь не найден')
    else:
        password2 = input("Введите пароль: ")
        cursor.execute("SELECT password_hash, password_salt FROM users WHERE username=?", [user_id])
        res = cursor.fetchone()
        if password_check(password2, res[0], res[1]):
            print("Вход выполнен")
        else:
            print("Пароль не верный")
