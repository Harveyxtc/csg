from flask import Flask
from routes.dashboard_routes import dashboard_blueprint

app = Flask(__name__)

app.register_blueprint(dashboard_blueprint)

if __name__ == "__main__":
    app.run(debug=True)