#!/usr/bin/env python3
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
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import msal
import requests
from authlib.integrations.flask_client import OAuth
from sqlalchemy.orm import DeclarativeBase
from db import *
from config import *
from utils import *
import sqlalchemy

logging.getLogger("werkzeug").setLevel(logging.ERROR)

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
    return User.query.filter_by(email=email).first()

# Route for authentication
@app.route("/authenticate")
def login():
    # Redirect to Azure AD authorization endpoint
    return azure.authorize_redirect(redirect_uri=config['redirect_uri'])

# Callback route for Azure AD
@app.route("/callback")
def callback():
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
    return render_template("ssh_entry.html", user=current_user)

# Logout route
@app.route("/logout")
@flask_login.login_required
def logout():
    flask_login.logout_user()
    return render_template("landing.html")

# Error handler for 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# Error handler for 403
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

# Route to get current user ID
@app.route("/whoami")
@flask_login.login_required
def whoami():
    return str(current_user.get_id())

# Landing page route
@app.route("/landing")
def landing():
    return render_template("landing.html")

# Home page route
@app.route("/home")
@flask_login.login_required
def home():
    return render_template("home.html")

# Route to manage challenges
@app.route("/challenges", methods=["GET", "POST"])
@flask_login.login_required
def manage_challenges():
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
    return render_template("terminal.html")

# Function to set terminal window size
def set_winsize(fd, row, col, xpix=0, ypix=0):
    logging.debug("Setting window size with termios")
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

# Function to read and forward PTY output
def read_and_forward_pty_output(user_id):
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
            logging.info("Error forwarding data, closing session")
            redis_client.delete(f"session:{user_id}")

# SocketIO event handler for PTY input
@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    if not current_user.is_authenticated:
        print("Rejected unauthenticated user")
        return
    
    user_id = current_user.get_db_id()
    fd = redis_client.hget(f"session:{user_id}", "fd")
    
    if fd:
        fd = int(fd)
        print("Received input from browser: %s" % data["input"])
        os.write(fd, data["input"].encode())

# SocketIO event handler for terminal resize
@socketio.on("resize", namespace="/pty")
def resize(data):
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
    if not current_user.is_authenticated:
        print("Rejected unauthenticated user")
        return

    logging.info("New client connected")
    join_room(current_user.email)

    user_id = current_user.get_db_id()
    pid = redis_client.hget(f"session:{user_id}", "pid")
    fd = redis_client.hget(f"session:{user_id}", "fd")

    if pid and fd:
        pid, fd = int(pid), int(fd)
        alive_child = check_pid(pid)
        open_fd = is_fd_open(fd)

        if alive_child:
            os.kill(pid, 15)

        if open_fd:
            os.close(fd)

        subprocess.run(
            [
                "/usr/bin/podman",
                "rm",
                "--time",
                "1",
                "--force",
                current_user.container_name,
            ]
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
    if config["run_mode"] == "dev":
        socketio.run(app, debug=True, port=5000, host="0.0.0.0")
    else:
        socketio.run(app, debug=False, port=5000, host="0.0.0.0")


if __name__ == "__main__":
    main()