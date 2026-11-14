import flask
app = flask.Flask(__name__)

@app.route('/hi')
def hi():
    return flask.render_template_string(flask.request.args.get('t'))
