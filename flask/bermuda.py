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
import flask_login


logging.getLogger("werkzeug").setLevel(logging.ERROR)

__version__ = "0.5.0.2"

app = Flask(__name__, template_folder="./templates", static_folder="./static", static_url_path="")
app.config["SECRET_KEY"] = "secret!"
app.config["cmd"] = "cat /etc/os-release"
app.config["podman_uri"] = "unix:///run/user/1000/podman/podman.sock"
app.config["active_sessions"] = {}
socketio = SocketIO(app)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

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
        return '''
               <form action='authenticate' method='POST'>
                <input type='text' name='email' id='email' placeholder='email'/>
                <input type='submit' name='submit'/>
               </form>
               '''

    email = flask.request.form['email']
    user = User()
    user.id = email
    flask_login.login_user(user)
    return flask.redirect(flask.url_for('terminal'))

    return 'Bad login'

@app.route("/")
@flask_login.login_required
def index():
    return render_template("ssh_entry.html")

@app.route("/landing")
def landing():
    return render_template("landing.html")

@app.route("/terminal")
@flask_login.login_required
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
    """write to the child pty. The pty sees this as if you are typing in a real
    terminal.
    """
    if app.config["fd"]:
        logging.debug("received input from browser: %s" % data["input"])
        os.write(app.config["fd"], data["input"].encode())


@socketio.on("resize", namespace="/pty")
def resize(data):
    if app.config["fd"]:
        logging.debug(f"Resizing window to {data['rows']}x{data['cols']}")
        set_winsize(app.config["fd"], data["rows"], data["cols"])


@socketio.on("connect", namespace="/pty")
def connect():
    """new client connected"""

    if not current_user.is_authenticated:
       return; 
    
    logging.info("new client connected")
    if app.config["active_sessions"][current_user.name]:
        # already started child process, don't start another
        return

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