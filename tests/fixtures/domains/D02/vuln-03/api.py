import flask, flask_cors
app = flask.Flask(__name__)
flask_cors.CORS(app, origins='*', supports_credentials=True)
