#!/usr/bin/env python3
import argparse
from flask import Flask, render_template
from flask_socketio import SocketIO
import flask
import pty
import os
import subprocess
import select
import termios
import struct
import fcntl
import shlex
import logging
import sys
import socket
import requests
import time
import msal
import flask_login
from flask_login import current_user
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from db import *

db = SQLAlchemy(model_class=Base)

logging.getLogger("werkzeug").setLevel(logging.ERROR)

__version__ = "0.5.0.2"

app = Flask(__name__, template_folder="./templates", static_folder="./static", static_url_path="")
app.config["SECRET_KEY"] = "secret!"
app.config["cmd"] = "cat /etc/os-release"
app.config["podman_uri"] = "unix:///run/user/1000/podman/podman.sock"
socketio = SocketIO(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)

with app.app_context():
    db.create_all()

CLIENT_ID = 
CLIENT_SECRET = 
TENANT_ID = 'common'  # 'common' for multi-tenant
AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
SCOPES = ['User.Read']

app_msal = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY)

class User(flask_login.UserMixin):
    pass

@login_manager.user_loader
def user_loader(email):
    user = User()
    user.id = email
    return user


@app.route("/authenticate", methods=['GET', 'POST'])
def authenticate():
    if flask.request.method == 'GET':
        device_code_response = app_msal.initiate_device_flow(scopes=SCOPES)
        
        if 'user_code' not in device_code_response:
            return f"Failed to create device flow. Error: {device_code_response.get('error_description')}"

        flask.session['device_code_response'] = device_code_response
        #I think this template will be jakes html page instead of this blank page... but yeah
        return render_template("""
            <html>
                <body> 
                    <h2>To authenticate, please visit the following URL:</h2>
                    <p><a href="{{ device_code_response['verification_uri'] }}" target="_blank">{{ device_code_response['verification_uri'] }}</a></p>
                    <p>And enter the following code:</p>
                    <p><strong>{{ device_code_response['user_code'] }}</strong></p>
                </body>
            </html>
        """, device_code_response=device_code_response)
        # return '''
        #        <form action='authenticate' method='POST'>
        #         <input type='text' name='email' id='email' placeholder='email'/>
        #         <input type='submit' name='submit'/>
        #        </form>
        #        '''
    # Handle POST request -> helped with error handling for auth 
    device_code_response = flask.session.get('device_code_response')

    if not device_code_response:
        return "Error: device flow is not initialized."

    #if the request worked -> gets access token to get user information 
    while True:
        result = app_msal.acquire_token_by_device_flow(device_code_response)

        if "access_token" in result:
            access_token = result['access_token']
            break
        elif "error" in result and result['error'] != "authorization_pending":
            print(f"Error: {result.get('error_description')}")
            return f"Error: {result.get('error_description')}"

        time.sleep(device_code_response['interval'])

    # getting user info based off token
    user_info_response = requests.get(
        'https://graph.microsoft.com/v1.0/me',
        headers={'Authorization': f'Bearer {access_token}'}
    )

    if user_info_response.status_code == 200:
        user_info = user_info_response.json()
        email = user_info.get('mail') or user_info.get('userPrincipalName')

        # Check if the user's email ends with @uoregon.edu
        if email and email.endswith('@uoregon.edu'):
            user = User()
            user.id = email
            flask_login.login_user(user)
            return flask.redirect(flask.url_for('terminal'))

        else:
            #im not sure if this will work atm, testing is needed :) 
            return "Authentication successful, but only @uoregon.edu accounts are allowed."

    else:
        return f"Failed to fetch user info: {user_info_response.status_code}, {user_info_response.text}"
    #this info was replaced from authentication !!
    #email = flask.request.form['email']
    #user = User()
    #user.id = email
    #flask_login.login_user(user)
    #return flask.redirect(flask.url_for('terminal'))

    #return 'Bad login'

@app.route("/")
@flask_login.login_required
def index():
    return render_template("ssh_entry.html")

@flask_login.login_required
@app.route("/whoami")
def whoami():
    return current_user.id

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/terminal")
#@flask_login.login_required
def terminal():
    return render_template("terminal.html")

def set_winsize(fd, row, col, xpix=0, ypix=0):
    logging.debug("setting window size with termios")
    winsize = struct.pack("HHHH", row, col, xpix, ypix)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


def read_and_forward_pty_output():
    max_read_bytes = 1024 * 20
    while True:
        socketio.sleep(0.01)
        if app.config["fd"]:
            timeout_sec = 0
            (data_ready, _, _) = select.select([app.config["fd"]], [], [], timeout_sec)
            if data_ready:
                output = os.read(app.config["fd"], max_read_bytes).decode(
                    errors="ignore"
                )
                socketio.emit("pty-output", {"output": output}, namespace="/pty")

@socketio.on("pty-input", namespace="/pty")
def pty_input(data):
    print(current_user.id)
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    if app.config["fd"]:
        logging.debug("received input from browser: %s" % data["input"])
        os.write(app.config["fd"], data["input"].encode())


@socketio.on("resize", namespace="/pty")
def resize(data):
    print(current_user.id)
    if app.config["fd"]:
        logging.debug(f"Resizing window to {data['rows']}x{data['cols']}")
        set_winsize(app.config["fd"], data["rows"], data["cols"])


@socketio.on("connect", namespace="/pty")
def connect():
    """new client connected"""

    print(current_user.id)
    if not current_user.is_authenticated:
       return; 
    
    logging.info("new client connected")
    # if current_user.id in app.config["active_sessions"].keys():
    #     # already started child process, don't start another
    #     return

    # create child process attached to a pty we can read from and write to
    (child_pid, fd) = pty.fork()
    if child_pid == 0:
        # this is the child process fork.
        # anything printed here will show up in the pty, including the output
        # of this subprocess
        subprocess.run(app.config["cmd"])
    else:
        # this is the parent process fork.
        # store child fd and pid
        app.config["fd"] = fd
        app.config["active_sessions"] = child_pid
        set_winsize(fd, 50, 50)
        cmd = " ".join(shlex.quote(c) for c in app.config["cmd"])
        # logging/print statements must go after this because... I have no idea why
        # but if they come before the background task never starts
        socketio.start_background_task(target=read_and_forward_pty_output)

        logging.info("child pid is " + child_pid)
        logging.info(
            f"starting background task with command `{cmd}` to continously read "
            "and forward pty output to client"
        )
        logging.info("task started")


def main():
    socketio.run(app, debug=True, port=8080, host="0.0.0.0")

if __name__ == '__main__':
    main()