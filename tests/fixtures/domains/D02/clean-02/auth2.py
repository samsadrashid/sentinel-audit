import jwt

def user(token, key):
    return jwt.decode(token, key, algorithms=['RS256'], audience='api')
