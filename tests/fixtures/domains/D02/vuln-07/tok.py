import jwt

def read(t, k):
    return jwt.decode(t, k, algorithms=['HS256', 'none'])
