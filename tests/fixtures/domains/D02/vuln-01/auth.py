import jwt

def user(token):
    return jwt.decode(token, options={'verify_signature': False})
