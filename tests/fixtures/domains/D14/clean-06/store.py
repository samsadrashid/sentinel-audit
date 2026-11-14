import sqlalchemy

def q(conn, sku):
    return conn.execute(sqlalchemy.text('SELECT * FROM items WHERE sku = :sku'), {'sku': sku})
