import flask
app = flask.Flask(__name__)

@app.get('/f')
def f():
    return flask.send_from_directory('/srv/data', 'report.txt')
