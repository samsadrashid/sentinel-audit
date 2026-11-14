import jwt

def claims(t, key):
    return jwt.decode(t, key, algorithms=['ES256'])
