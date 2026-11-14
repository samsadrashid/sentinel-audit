import flask, os
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = os.environ['APP_SECRET_KEY']
