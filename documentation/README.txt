# Project Bermuda

Educational platform for University of Oregon students to practice cybersecurity skills.

Similar to “Hack the Box” or other CTF platforms, but more accessible to those who are new.

Securely give access to authorized users to vulnerable servers to learn some ethical hacking tools and practices.

## Course name
CS 422 (Fall 2024; 11613) Software Method I

## Authors 
**Made by Python Pirates**

Emily Clauson - Alexandr Iapara - Jake Khal - Stephen Swanson


## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the required packages

Install required packages:
```bash
cd flask
pip install -r requirements.txt
```
Decrypt the credentials file and deploy the application:
```bash
cd flask/config
cp credentials.json.enc credentials.json
ansible-vault decrypt credentials.json
[Enter Secret Phrase]
cd ..
python3 routes.py
```
## Usage
Open the browser of your preference and enter the following URL to access the website locally:
```
localhost:5000
```
or
```
127.0.0.1:5000
```

Project Bermuda is also hosted on University of Oregon's Cybersecurity Club server.

You can access Project Bermuda by following the following URL:
```
terminal-development.uosec.org
```

## Highlight Video
Follow the link to access the highlight video:

Video Link: https://youtu.be/sv3lvB-_bHM

## Technologies Used
Python, Flask, HTML, CSS, Ansible, MariaDB, Caddy, MSAL/OIDC Module, Azure

## File creation date
The following README file was created: 10/7/2024

Last modification of this file was on: 12/6/2024

## Links
Access Link: https://terminal-development.uosec.org/

Video Link: https://youtu.be/sv3lvB-_bHM

## License
[MIT](https://choosealicense.com/licenses/mit/)
