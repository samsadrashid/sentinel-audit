import flask
from models import Order
app = flask.Flask(__name__)

@app.post('/o')
def new():
    return Order(**flask.request.get_json())
