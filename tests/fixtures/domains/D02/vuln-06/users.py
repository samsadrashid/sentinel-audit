import flask
from models import User
app = flask.Flask(__name__)

@app.post('/u')
def create():
    return User(**flask.request.json)
