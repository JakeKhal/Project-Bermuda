from flask import Flask, redirect, request, url_for
from authlib.integrations.flask_client import OAuth
import os
import flask
import requests
import msal

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Set your Azure AD credentials
CLIENT_ID = 
CLIENT_SECRET = # Use an environment variable for security
TENANT_ID = 'common'  # for multi-tenant authentication
AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
SCOPES = ['User.Read']
REDIRECT_URI = 'http://localhost:5000/callback'


# MSAL ConfidentialClientApplication
app_msal = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET,  # Pass CLIENT_SECRET directly as a string
)


# Set up the OAuth client
oauth = OAuth(app)
azure = oauth.register(
    name='azure',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=f'{AUTHORITY}/oauth2/v2.0/authorize',
    access_token_url=f'{AUTHORITY}/oauth2/v2.0/token',
    client_kwargs={'scope': 'openid profile email User.Read'},
    redirect_uri=REDIRECT_URI,
)

# Route to initiate authentication
#@app.route('/')
#def index():
#    return '<a href="/login">Log in with Azure AD</a>'

# Route for login
@app.route('/')
def login():
    # Redirect to Azure AD authorization endpoint
    return azure.authorize_redirect(redirect_uri=REDIRECT_URI)

# Callback route
@app.route('/callback')
def callback():
    # Get the authorization code from the query parameters
    code = request.args.get('code')
    if not code:
        return "Authorization failed: No authorization code provided."

    # Exchange the authorization code for tokens using MSAL
    result = app_msal.acquire_token_by_authorization_code(
        code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    if "access_token" in result:
        access_token = result["access_token"]

        # Fetch user information
        user_info_response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {access_token}'}
        )

        if user_info_response.status_code == 200:
            user_info = user_info_response.json()
            email = user_info.get('mail') or user_info.get('userPrincipalName')

            # Check if the user's email ends with @uoregon.edu
            if email and email.endswith('@uoregon.edu'):
                return f"Yay! Successfully authenticated as {email}"
            else:
                return "Authentication successful, but only @uoregon.edu accounts are allowed."

        else:
            return f"Failed to fetch user info: {user_info_response.status_code}, {user_info_response.text}"

    return f"Failed to acquire token: {result.get('error_description')}"

# Run the Flask app
if __name__ == '__main__':
    app.run(port=5000)
