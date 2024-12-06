"""
File: config.py
Purpose: This file loads and configures the necessary settings for Project Bermuda.
Creation Date: 2024-11-12
Authors: Stephen Swanson

This file is part of Project Bermuda, an educational platform for University of Oregon students to practice cybersecurity skills.
It loads credentials, configuration settings, and challenge data from external files.

Modifications:
- 2024-11-12: File created
- 2024-11-27: Connected challenge page to database
- 2024-12-03: Updated redirect URL for Azure AD authentication and removed port number
- 2024-12-05: Removed redirect URI and added it to ansible/files/prod_config.json
"""

import os
import yaml
import json

# Load credentials from JSON file
with open("config/credentials.json", "r") as file:
    credentials = json.load(file)

# Extract necessary credentials
CLIENT_ID = credentials["CLIENT_ID"]
CLIENT_SECRET = credentials["CLIENT_SECRET"]
TENANT_ID = credentials["TENANT_ID"]
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]

# Load general configuration from JSON file
with open("config/config.json", "r") as file:
    config = json.load(file)

# Initialize an empty dictionary to store challenges
challenges = {}

# Load challenge data from YAML files in the specified directory
path = "config/challenges"
for file_name in os.listdir(path):
    if file_name.endswith(".yaml") or file_name.endswith(".yml"):
        file_path = os.path.join(path, file_name)
        with open(file_path, "r") as file:
            data = yaml.safe_load(file)
            challenges.update(data)