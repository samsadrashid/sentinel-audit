import psycopg2

def connect(host):
    return psycopg2.connect(host=host, dbname='app', sslmode='verify-full')
