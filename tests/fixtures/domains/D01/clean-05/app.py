import flask
app = flask.Flask(__name__)

@app.route('/hi')
def hi():
    return flask.render_template('hi.html', name=flask.request.args.get('n'))
