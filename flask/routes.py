#!/usr/bin/env python3
"""
File: routes.py
Purpose: This file defines the routes and main functionality for Project Bermuda, which is a Flask web application.
Creation Date: 2024-11-12
Authors: Stephen Swanson, Alexandr Iapara, Emily Clauson, Jake Khal

This file contains the main routes and functionality for the Project Bermuda web application. It includes routes for
authentication, managing challenges, the terminal, and other pages. It also includes SocketIO event handlers for
interacting with the terminal.

Modifications:
- 2024-11-12: Initial version.
- 2024-11-25: Working implementation with user authentication via Azure AD, real-time terminal sessions using Flask-SocketIO, 
and various routes for rendering templates and managing terminal sessions.
- 2024-11-26: Configured routes for html files and added error handlers for 404 and 403.
- 2024-11-27: Added manage_challenges route to handle challenge validation and solving.
- 2024-11-30: Fixed submit correct flag not functioning properly.
- 2024-12-03: Added extra configs for database and run mode.
- 2024-12-05: Removed REDIRECT_URI and added config for redirect_uri.
- 2024-12-05: Added better error handling
- 2024-12-05: Added FlaskRedis for caching
"""

# Import necessary libraries and modules
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, join_room
from flask_redis import FlaskRedis
from fakeredis import FakeRedis
import flask
import pty
import os
import subprocess
import select
import termios
import uuid
import struct
import fcntl
import logging
import sys
import socket
import json
import flask_login
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
import msal
import requests
from authlib.integrations.flask_client import OAuth
from sqlalchemy.orm import DeclarativeBase
from db import *
from config import *
from utils import *
import sqlalchemy

# Set logging level for werkzeug
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# Define the version of the application
__version__ = "0.5.0.2"

# Initialize Flask app
app = Flask(
    __name__,
    template_folder="./templates",
    static_folder="./static",
    static_url_path="",
)

# Configure app
app.config["SECRET_KEY"] = credentials["FLASK_SECRET"]
socketio = SocketIO(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "/landing"

# Set database URI based on run mode
if config["run_mode"] == "dev":
    app.config["SQLALCHEMY_DATABASE_URI"] = credentials["DEV_DATABASE_STRING"]
    redis_client = FlaskRedis.from_custom_provider(FakeRedis)
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = credentials["PROD_DATABASE_STRING"]
    app.config['REDIS_URL'] = credentials["REDIS_STRING"]
    redis_client = FlaskRedis()
db.init_app(app)
redis_client.init_app(app)

redis_client.flushall()

# MSAL ConfidentialClientApplication
app_msal = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,  # Pass CLIENT_SECRET directly as a string
)

# Configure OAuth for Azure
oauth = OAuth(app)
azure = oauth.register(
    name="azure",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=f"{AUTHORITY}/oauth2/v2.0/authorize",
    access_token_url=f"{AUTHORITY}/oauth2/v2.0/token",
    client_kwargs={"scope": "openid profile email User.Read"},
    redirect_uri=config['redirect_uri'],
)

# Create all database tables
with app.app_context():
    db.create_all()

# User loader for Flask-Login
@login_manager.user_loader
def user_loader(email):
    """
    Load user by email.
    Args:
        email (str): User's email address.
    Returns:
        User: User object if found, else None.
    """
    return User.query.filter_by(email=email).first()

# Route for authentication
@app.route("/authenticate")
def login():
    """
    Redirect to Azure AD authorization endpoint.
    Returns:
        Response: Redirect response to Azure AD.
    """
    return azure.authorize_redirect(redirect_uri=config['redirect_uri'])

# Callback route for Azure AD
@app.route("/callback")
def callback():
    """
    Handle the callback from Azure AD after authentication.
    Returns:
        Response: Redirect to index or error message.
    """
    # Get the authorization code from the query parameters
    code = request.args.get("code")
    if not code:
        return "Authorization failed: No authorization code provided."

    # Exchange the authorization code for tokens using MSAL
    result = app_msal.acquire_token_by_authorization_code(
        code, scopes=SCOPES, redirect_uri=config['redirect_uri']
    )

    if "access_token" in result:
        access_token = result["access_token"]

        # Fetch user information
        user_info_response = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            email = user_info.get("mail") or user_info.get("userPrincipalName")

            # Check if the user's email ends with @uoregon.edu
            if email and email.endswith("@uoregon.edu"):
                user = User.query.filter_by(email=email).first()
                if user is None:
                    user = User(email=email, container_name=str(uuid.uuid4()))
                    db.session.add(user)
                    db.session.commit()
                flask_login.login_user(user)
                return flask.redirect(flask.url_for("index"))

            else:
                return "Authentication successful, but only @uoregon.edu accounts are allowed."

        else:
            return f"Failed to fetch user info: {user_info_response.status_code}, {user_info_response.text}"

    return f"Failed to acquire token: {result.get('error_description')}"

# Index route
@app.route("/")
@flask_login.login_required
def index():
    """
    Render the SSH entry page.
    Returns:
        Response: Rendered template for SSH entry.
    """
    return render_template("ssh_entry.html", user=current_user)

# Logout route
@app.route("/logout")
@flask_login.login_required
def logout():
    """
    Log out the current user.
    Returns:
        Response: Rendered template for landing page.
    """
    flask_login.logout_user()
    return render_template("landing.html")

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    """
    Handle 404 errors.
    Args:
        e (Exception): Exception object.
    Returns:
        Response: Rendered template for 404 error.
    """
    return render_template("404.html"), 404

# Error handler for 403
@app.errorhandler(403)
def forbidden(e):
    """
    Handle 403 errors.
    Args:
        e (Exception): Exception object.
    Returns:
        Response: Rendered template for 403 error.
    """
    return render_template("403.html"), 403

# Route to get current user ID
@app.route("/whoami")
@flask_login.login_required
def whoami():
    """
    Get the current user's ID.
    Returns:
        str: Current user's ID.
    """
    return str(current_user.get_id())

# Landing page route
@app.route("/landing")
def landing():
    """
    Render the landing page.
    Returns:
        Response: Rendered template for landing page.
    """
    return render_template("landing.html")

# Home page route
@app.route("/home")
@flask_login.login_required
def home():
    """
    Render the home page.
    Returns:
        Response: Rendered template for home page.
    """
    return render_template("home.html")

# Route to manage challenges
@app.route("/challenges", methods=["GET", "POST"])
@flask_login.login_required
def manage_challenges():
    """
    Manage challenges for the user.
    Methods:
        GET: Return the list of challenges.
        POST: Validate and solve a challenge.
    Returns:
        Response: JSON response with challenge data or status message.
    """
    if request.method == "GET":
        solved_challenges = []
        for solve in Challenge_Solve.query.filter_by(user_id=current_user.id).all():
            solved_challenges.append(solve.challenge_id)

        user_challenges = []
        for challenge_id in challenges.keys():
            challenge = {
                "id": challenge_id,
                "title": challenges[challenge_id]["title"],
                "summary": challenges[challenge_id]["summary"],
                "description": challenges[challenge_id]["description"],
                "completed": challenge_id in solved_challenges,
            }
            user_challenges.append(challenge)
        return jsonify(user_challenges)

    elif request.method == "POST":
        data = request.get_json()
        challenge_id = data.get("challenge_id")
        flag = data.get("flag")

        if not challenge_id or not flag:
            print("Missing challenge_id or flag")
            return jsonify({"status": "err", "message": "Missing challenge_id or flag"})

        # Validate the challenge ID
        if challenge_id not in challenges:
            print(f"Invalid challenge ID: {challenge_id}")
            return jsonify({"status": "err", "message": "Invalid challenge ID"})

        # Debugging: Print the received flag and the expected flag
        print(f"Received flag for challenge {challenge_id}: '{flag}'")
        print(f"Expected flag for challenge {challenge_id}: '{challenges[challenge_id]['flag']}'")

        # Check if the flag is correct
        if challenges[challenge_id]["flag"].strip() == flag.strip():
            # Check if the user has already solved the challenge
            existing_solve = Challenge_Solve.query.filter_by(user_id=current_user.id, challenge_id=challenge_id).first()
            if existing_solve:
                print(f"Challenge {challenge_id} already solved by user {current_user.id}")
                return jsonify({"status": "err", "message": "Challenge already solved"})

            # Mark the challenge as solved
            new_solve = Challenge_Solve(
                challenge_id=challenge_id,
                user_id=current_user.id
            )
            db.session.add(new_solve)
            try:
                db.session.commit()
                print(f"Challenge {challenge_id} solved by user {current_user.id}")
                return jsonify({"status": "ok", "message": "Challenge solved successfully!"})
            except sqlalchemy.exc.IntegrityError as e:
                db.session.rollback()
                print(f"IntegrityError: {e}")
                return jsonify({"status": "err", "message": "Database error: Challenge already solved"})
        else:
            print(f"Incorrect flag for challenge {challenge_id}")
            return jsonify({"status": "err", "message": "Incorrect flag"})

# Terminal route
@app.route("/terminal")
@flask_login.login_required
def terminal():
    """
    Render the terminal page.
    Returns:
        Response: Rendered template for terminal page.
    """
    return render_template("terminal.html")

# Function to set terminal window size
def set_winsize(fd, row, col, xpix=0, ypix=0):
    """
    Set the terminal window size.
    Args:
        fd (int): File descriptor.
        row (int): Number of rows.
        col (int): Number of columns.
        xpix (int): Pixel width (default 0).
        ypix (int): Pixel height (default 0).
    """
    logging.debug("Setting window size with termios")
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

# Function to read and forward PTY output
def read_and_forward_pty_output(user_id):
    """
    Read and forward PTY output to the client.
    Args:
        user_id (int): User ID.
    """
    max_read_bytes = 1024 * 20
    while True:
        try:
            user_email = redis_client.hget(f"user:{user_id}", "email")
            pid = redis_client.hget(f"session:{user_id}", "pid")
            fd = redis_client.hget(f"session:{user_id}", "fd")
            if not pid or not fd:
                return
            
            pid, fd = int(pid), int(fd)
            alive_child = check_pid(pid)
            open_fd = is_fd_open(fd)

            if not (alive_child and open_fd):
                redis_client.delete(f"session:{user_id}")
                return

            socketio.sleep(0.01)
            timeout_sec = 10
            (data_ready, _, _) = select.select([fd], [], [], timeout_sec)
            if data_ready:
                output = os.read(fd, max_read_bytes).decode(errors="ignore")
                print(f"forwarding data {output}, from fd {fd} to room {user_email}")
                socketio.emit(
                    "pty-output",
                    {"output": output},
                    namespace="/pty",
                    room=user_email.decode("utf-8"),
                )
        except:
            print("Error forwarding data, closing session")
            redis_client.delete(f"session:{user_id}")

# SocketIO event handler for PTY input
@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    """
    Handle PTY input from the client.
    Args:
        data (dict): Data containing the input.
    """
    if not current_user.is_authenticated:
        print("Rejected unauthenticated user")
        return
    
    user_id = current_user.get_db_id()
    fd = redis_client.hget(f"session:{user_id}", "fd")
    
    if fd:
        fd = int(fd)
        try:
            print("Received input from browser: %s" % data["input"])
            os.write(fd, data["input"].encode())
        except:
            print("Error forwarding data, closing session")
            redis_client.delete(f"session:{user_id}")

# SocketIO event handler for terminal resize
@socketio.on("resize", namespace="/pty")
def resize(data):
    """
    Handle terminal resize event.
    Args:
        data (dict): Data containing the new size.
    """
    if not current_user.is_authenticated:
        print("Rejected unauthenticated user")
        return

    user_id = current_user.get_db_id()
    fd = redis_client.hget(f"session:{user_id}", "fd")

    if fd:
        fd = int(fd)
        logging.debug(f"Resizing window to {data['rows']}x{data['cols']}")
        set_winsize(fd, data["rows"], data["cols"])

# SocketIO event handler for client connection
@socketio.on("connect", namespace="/pty")
def connect(auth):
    """
    Handle new client connection.
    Args:
        auth (dict): Authentication data.
    """
    if not current_user.is_authenticated:
        print("Rejected unauthenticated user")
        return

    logging.info("New client connected")
    join_room(current_user.email)

    user_id = current_user.get_db_id()
    pid = redis_client.hget(f"session:{user_id}", "pid")
    fd = redis_client.hget(f"session:{user_id}", "fd")

    if pid or fd:
        pid, fd = int(pid), int(fd)
        alive_child = check_pid(pid)
        open_fd = is_fd_open(fd)

        if alive_child:
            os.kill(pid, 15)

        if open_fd:
            os.close(fd)

        # Suppress output of subprocess.run
        print("Cleaning up old session... Please wait")
        subprocess.run(
            [
                "/usr/bin/podman",
                "rm",
                "--time",
                "1",
                "--force",
                current_user.container_name,
            ],
            stdout=subprocess.DEVNULL,  # Redirect standard output to /dev/null
            stderr=subprocess.DEVNULL,  # Redirect standard error to /dev/null
        )

        redis_client.delete(f"session:{user_id}")
    # Start new terminal session
    (child_pid, child_fd) = pty.fork()
    if child_pid == 0:
        # this is the child process fork.
        # anything printed here will show up in the pty, including the output
        # of this subprocess
        try:


            subprocess.run(
                [
                    "/usr/bin/podman",
                    "run",
                    "--rm",
                    "-it",
                    "--replace",
                    "--name",
                    current_user.container_name,
                    config["image_name"],
                ]
            )
        except:
            pass
        return
    else:
        redis_client.hmset(
            f"session:{user_id}",
            {"pid": child_pid, "fd": child_fd, "container_name": current_user.container_name}
        )
        redis_client.hset(f"user:{user_id}", "email", current_user.email)
        set_winsize(child_fd, 50, 50)
        socketio.start_background_task(
            target=read_and_forward_pty_output, user_id=user_id
        )

        logging.info("Child pid is " + str(child_pid))
        logging.info("Task started")


def check_pid(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def is_fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False

# Main function to run the app
def main():
    """
    Run the Flask application.
    """
    if config["run_mode"] == "dev":
        socketio.run(app, debug=True, port=5000, host="0.0.0.0")
    else:
        socketio.run(app, debug=False, port=5000, host="0.0.0.0", allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()