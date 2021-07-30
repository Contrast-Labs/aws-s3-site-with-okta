import getpass
import json
import secrets

import boto3

secrets_client = boto3.client("secretsmanager")

secret_name = input("Paste the secret name from terraform output: ")
okta_client_id = input("Okta client id: ").strip()
okta_secret = getpass.getpass(prompt="Okta client secret: ").strip()
okta_domain_name = input("Okta domain name: ").strip()
website_domain_name = input("Website Domain Name: ").strip()
jwt_key = secrets.token_hex(64)

settings = {
    "AUTH_REQUEST": {
        "client_id": okta_client_id,
        "response_type": "code",
        "scope": "openid email",
        "redirect_uri": f"https://{website_domain_name}/_callback",
    },
    "TOKEN_REQUEST": {
        "client_id": okta_client_id,
        "redirect_uri": f"https://{website_domain_name}/_callback",
        "grant_type": "authorization_code",
        "client_secret": okta_secret,
    },
    "JWT_KEY": jwt_key,
    "DISCOVERY_DOCUMENT": f"https://{okta_domain_name}/.well-known/openid-configuration",
    "SESSION_DURATION": 300,
    "BASE_URL": f"https://{okta_domain_name}",
    "CALLBACK_PATH": "/_callback",
    "DOMAIN_NAME": f"https://{website_domain_name}",
}

secrets_client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(settings))
