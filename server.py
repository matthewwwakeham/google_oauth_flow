# server.py

import json

import os
from dotenv import load_dotenv
import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, redirect, render_template, session, url_for

# Load environment variables from the .env file in the variables folder
load_dotenv(dotenv_path="variables/.env")

app = Flask(__name__)

# Configuration from environment variables
app.secret_key = os.getenv("FLASK_SECRET")

SERVER_METADATA_URL = "https://accounts.google.com/.well-known/openid-configuration"

oauth = OAuth(app)
oauth.register(
    "myApp",
    client_id=os.getenv("OAUTH2_CLIENT_ID"),
    client_secret=os.getenv("OAUTH2_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid email",
    },
    server_metadata_url=SERVER_METADATA_URL,
)

# Routes
@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"),
                           pretty=json.dumps(session.get("user"), indent=4))

@app.route("/signin-google")
def googleCallback():
    # fetch access token and id token using authorization code
    token = oauth.myApp.authorize_access_token()

    # fetch user data with access token
    # Extract the email from the ID token
    user_info = token.get("userinfo")
    email = user_info["email"]

    # set complete user information in the session
    session["user"] = token
    return redirect(url_for("home"))

@app.route("/google-login")
def googleLogin():
    if "user" in session:
        return redirect(url_for("home"))
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)