import flask
from models import User
app = flask.Flask(__name__)

@app.post('/u')
def create():
    d = flask.request.json
    return User(name=d['name'])
