def find(cur, uid):
    cur.execute('SELECT * FROM users WHERE id = %(id)s', {'id': uid})
