import flask, os
app = flask.Flask(__name__)

@app.get('/f')
def f():
    return open(os.path.join('/srv/data', flask.request.args.get('name'))).read()
