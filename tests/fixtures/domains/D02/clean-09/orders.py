import flask
from models import Order
app = flask.Flask(__name__)

@app.post('/o')
def new():
    body = flask.request.get_json()
    return Order(sku=body['sku'], qty=int(body['qty']))
