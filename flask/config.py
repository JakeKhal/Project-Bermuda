import os
import yaml
import json

with open("config/credentials.json", "r") as file:
    credentials = json.load(file)

CLIENT_ID = credentials["CLIENT_ID"]
CLIENT_SECRET = credentials["CLIENT_SECRET"]
TENANT_ID = credentials["TENANT_ID"]
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]
REDIRECT_URI = "https://terminal-development.uosec.org/callback"

with open("config/config.json", "r") as file:
    config = json.load(file)

challenges = {}
path = "config/challenges"
for file_name in os.listdir(path):
    if file_name.endswith(".yaml") or file_name.endswith(".yml"):
        file_path = os.path.join(path, file_name)
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)
            challenges.update(data)
