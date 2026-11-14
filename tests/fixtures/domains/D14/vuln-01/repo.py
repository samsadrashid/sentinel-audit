def find(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()
