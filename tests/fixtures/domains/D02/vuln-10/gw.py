import jwt, flask
app = flask.Flask(__name__)

def claims(t):
    return jwt.decode(t, options={'verify_signature': False})

if __name__ == '__main__':
    app.run(debug=True)
