import flask, requests
app = flask.Flask(__name__)

@app.get('/p')
def proxy():
    return requests.get(flask.request.args.get('url')).text
