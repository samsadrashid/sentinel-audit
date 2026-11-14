import jwt

def user(token, key):
    return jwt.decode(token, key, algorithms=['HS256'])
