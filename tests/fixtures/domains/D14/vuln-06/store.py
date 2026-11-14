import sqlalchemy

def q(conn, sku):
    return conn.execute(sqlalchemy.text(f"SELECT * FROM items WHERE sku = '{sku}'"))
