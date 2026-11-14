import flask
app = flask.Flask(__name__)

@app.route('/go')
def go():
    return flask.redirect(flask.request.args.get('next'))
