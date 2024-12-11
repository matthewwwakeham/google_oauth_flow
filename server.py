# server.py

# Imports
import json

import os
from dotenv import load_dotenv
import requests
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, redirect, render_template, session, url_for

# Load environment variables from the .env file in the variables folder
load_dotenv(dotenv_path="variables/.env")

# Create app
app = Flask(__name__)

# Configuration from environment variables
app.secret_key = os.getenv("FLASK_SECRET")

# Configure SQL Alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Database Model ~ Single Row with our DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    user_color = db.Column(db.String(7), unique=False, nullable=False)

# Google data
SERVER_METADATA_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth credentials
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
# Home
@app.route("/")
def home():
    return render_template("home.html", session=session.get("user"))

# Sign in
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

# Login
@app.route("/google-login")
def googleLogin():
    if "user" in session:
        return redirect(url_for("home"))
    return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))

# Sign up
@app.route("/signup")
def signup():
    return render_template("signup.html")

# Login non-Google auth
@app.route("/signin")
def signin():
    return render_template("signin.html")

# Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))

# Terms
@app.route("/terms")
def terms():
    return render_template("terms.html")

# Privacy
@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

# Cookies
@app.route("/cookies")
def cookies():
    return render_template("cookies.html")

# Run the script directly 
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8000, debug=True)