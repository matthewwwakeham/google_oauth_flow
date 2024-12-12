# server.py

# Imports
import json

import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, request, redirect, render_template, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from utils import get_random_color

# Load environment variables from the .env file in the variables folder
load_dotenv(dotenv_path="variables/.env")

# Create app
app = Flask(__name__)

# Configuration from environment variables
app.secret_key = os.getenv("FLASK_SECRET")

# Set session lifetime
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30) # Session expires after 30 minutes

# Configure SQL Alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Database Model ~ Single Row with our DB
class User(db.Model):
    __tablename__ = 'users'

    # User Information
    user_id = db.Column(db.Integer, primary_key=True)  # Unique user ID
    username = db.Column(db.String(25), unique=True, nullable=False)  # Username for all users
    email = db.Column(db.String(254), unique=True, nullable=False)  # Email address
    user_color = db.Column(db.String(7), nullable=False, default="#FFFFFF")  # A user-assigned or random color (e.g., #FFFFFF)
    
    # Account Activity
    active = db.Column(db.Boolean, default=True)  # Whether the user account is active
    created_at = db.Column(db.DateTime, default= lambda: datetime.now(tz=timezone.utc), nullable=False)  # Account creation timestamp
    last_login_at = db.Column(db.DateTime)  # Last login timestamp
    current_login_at = db.Column(db.DateTime)  # Current login timestamp
    last_login_ip = db.Column(db.String(100))  # IP address from the last login
    current_login_ip = db.Column(db.String(100))  # IP address from the current login
    login_count = db.Column(db.Integer, default=0)  # Number of logins

    # Authentication Fields
    auth_provider = db.Column(db.String(20), nullable=False, default="local")  # 'local', 'google', etc.
    oauth_id = db.Column(db.String(100), unique=True, nullable=True)  # OAuth ID for external providers
    password_hash = db.Column(db.String(128), nullable=True)  # Hashed password (nullable for OAuth users)

    # Membership/Subscription
    is_member = db.Column(db.Boolean, default=False, nullable=False)  # Default False
    membership_start_date = db.Column(db.DateTime, default=lambda: datetime.now(tz=timezone.utc), nullable=True)  # Membership start date
    membership_end_date = db.Column(db.DateTime, nullable=True)  # Membership end date

    # Role/Permissions
    role = db.Column(db.String(20), default="user", nullable=False)  # Role (e.g., admin, user)

    # Constraints and Indexes
    __table_args__ = (
        db.UniqueConstraint('username', name='uq_username'),
        db.UniqueConstraint('email', name='uq_email'),
        db.Index('ix_email', 'email'),  # Index for faster lookup
    )

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
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():
    # Pass user data to dashboard
    user = session.get("user")
    if not user:
        return redirect(url_for("signin"))
    return render_template("dashboard.html", user=user)

# Sign in
@app.route("/signin-google")
def googleCallback():
    # fetch access token and id token using authorization code
    token = oauth.myApp.authorize_access_token()
    user_info = token.get("userinfo") # Fetch user info

    # Extract the email from the ID token
    email = user_info.get("email")
    oauth_id = user_info.get("sub") # Google unique identifier

    # Does user exist?
    user = User.query.filter_by(oauth_id=oauth_id).first()

    if user:
        # Update existing user's login details
        user.last_login_at = user.current_login_at
        user.current_login_ip = request.remote_addr
        user.current_login_at = datetime.now(timezone.utc)
        user.login_count += 1
    else:

        # User color generation
        user_color = get_random_color()

        # Create a new user if not found
        user = User(
            username=None, # User will choose later
            email=email,
            oauth_id=oauth_id,
            auth_provider="google",
            user_color=user_color,
            created_at=datetime.now(timezone.utc),
            current_login_at=datetime.now(timezone.utc),
            current_login_ip=request.remote_addr,
            login_count=1
        )
        db.session.add(user)

    # Commit changes to db
    db.session.commit()

    # set complete user information in the session
    session.permanent = True  # This makes the session subject to `PERMANENT_SESSION_LIFETIME`
    session["user"] = {"email": email, "oauth_id": oauth_id, "user_color": user.user_color}
    return redirect(url_for("dashboard"))

# Login
@app.route("/google-login")
def googleLogin():
    try:
        if "user" in session:
            return redirect(url_for("dashboard"))
        return oauth.myApp.authorize_redirect(redirect_uri=url_for("googleCallback", _external=True))
    except Exception as e:
        # Log the error and provide user feedback
        print(f"Error during logn: {e}")
        return "An error occured during login. Please try again.", 500
    
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

# Accessibility
@app.route("/accessibility")
def accessibility():
    return render_template("accessibility.html")

# Help
@app.route("/helpcenter")
def helpcenter():
    return render_template("helpcenter.html")

# Feedback
@app.route("/sendfeedback")
def sendfeedback():
    return render_template("sendfeedback.html")

@app.before_request
def enforce_session_timeout():
    # Check if the session is active
    if "last_active" in session:
        last_active = session["last_active"]
        now = datetime.now(timezone.utc)
        
        # Compare last active time with the timeout
        if now - last_active > timedelta(minutes=30):  # 30-minute timeout
            session.clear()  # Clear the session if expired
            return redirect(url_for("login"))  # Redirect to login page
    
    # Update the last active time for the session
    session["last_active"] = datetime.now(timezone.utc)

# Run the script directly 
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8000, debug=True)