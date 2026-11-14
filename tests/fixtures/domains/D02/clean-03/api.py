import flask, flask_cors
app = flask.Flask(__name__)
flask_cors.CORS(app, origins=['https://app.example.org'], supports_credentials=True)
