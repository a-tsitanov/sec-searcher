import sqlite3


def find_users(name):
    with sqlite3.connect('users.db') as db:
        sql = "SELECT name FROM users WHERE name = '" + name + "'"
        return [row[0] for row in db.execute(sql).fetchall()]
