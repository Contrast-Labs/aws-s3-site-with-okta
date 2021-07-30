import calendar
import hashlib
import hmac
import json
import logging
import requests
import secrets
import urllib.parse

import boto3

from datetime import datetime
from http.cookies import BaseCookie
from http.cookies import Morsel
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple

from constants import FORBIDDEN_RESPONSE
from constants import INTERNAL_SERVER_ERROR
from constants import REMOVE_NONCE_COOKIE
from constants import REMOVE_TOKEN_COOKIE
from constants import UNAUTHORIZED_RESPONSE

from jose import jwt
from jose import JWTError
from jose import ExpiredSignatureError
from jose.exceptions import JWTClaimsError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

secrets_client = boto3.client("secretsmanager", region_name="us-east-1")

okta_config: Dict[str, Any] = {}
discovery_document: Dict[str, Any] = {}
jwks: Dict[str, Any] = {}

# Request structure: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html#example-viewer-request
HttpRequest = Dict[str, Any]
# Response structure: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-generating-http-responses-in-requests.html#lambda-generating-http-responses-object
HttpResponse = Dict[str, Any]
# Headers structure is described in response structure docs
HttpHeaders = Dict[str, List[Dict[str, str]]]
HttpParams = Dict[str, str]


class UnauthorizedRequest(Exception):
    """
    Raise this exception in helper functions that can't directly return the unauthorized response body
    """

    pass


class ForbiddenRequest(Exception):
    """
    Raise this exception in helper functions that can't directly return the forbidden response body
    """

    pass


def redirect_to_site(og_request_uri: str, user_email: str) -> HttpResponse:
    """
    Redirect the user to the protected site.

    Set a cookie with JWT to maintain the users session.
    """
    now = calendar.timegm(datetime.utcnow().utctimetuple())
    payload = {
        "aud": okta_config["DOMAIN_NAME"],
        "exp": str(now + int(okta_config["SESSION_DURATION"])),
        "email": user_email,
    }
    new_token = jwt.encode(payload, okta_config["JWT_KEY"], algorithm="HS512")

    token_cookie: Morsel = Morsel()
    token_cookie.set("TOKEN", new_token, new_token)
    token_cookie["path"] = "/"
    token_cookie["httponly"] = "true"
    token_cookie["secure"] = "true"

    return {
        "status": "302",
        "statusDescription": "Found",
        "body": "Id token retrieved",
        "headers": {
            "location": [{"key": "Location", "value": og_request_uri}],
            "set-cookie": [
                {"key": "Set-Cookie", "value": token_cookie.OutputString()},
                {"key": "Set-Cookie", "value": REMOVE_NONCE_COOKIE},
            ],
        },
    }


def validate_nonce(nonce: str, old_hash: str):
    """
    Validate the nonce set back by Okta by hashing it and comparing it
    to the hash that was sent in the 'NONCE' cookie during 'start_new_session'
    """
    new_hash = hmac.HMAC(bytes.fromhex(nonce), digestmod=hashlib.sha256).hexdigest()

    if not hmac.compare_digest(new_hash, old_hash):
        raise UnauthorizedRequest("Nonce validation failed")


def get_tokens(authorization_code: str) -> Tuple[str, str]:
    """
    Makes request to Okta's '/token' endpoint and returns the id token

    Endpoint details: https://developer.okta.com/docs/reference/api/oidc/#token
    """
    okta_config["TOKEN_REQUEST"]["code"] = authorization_code
    params = okta_config["TOKEN_REQUEST"]

    response = requests.post(discovery_document["token_endpoint"], params).json()

    if "error" in response:
        logger.error(response)
        raise UnauthorizedRequest("Error in token request response")

    return response["id_token"], response["access_token"]


def get_okta_public_key(id_token: str) -> Dict[str, Any]:
    """
    Check 'kid' value of id_token against those retrieved from okta endpoint
    and return the matching public key.
    """
    decoded_id_header = jwt.get_unverified_header(id_token)
    try:
        jwk = list(
            filter(lambda key: key["kid"] == decoded_id_header["kid"], jwks["keys"])
        )[0]

    except IndexError:
        raise UnauthorizedRequest("No matching public key found")

    return jwk


def verify_new_session(request_headers: HttpHeaders, request_params: HttpParams) -> str:
    """
    1) Verify that there are no errors in the okta response and all the required info is present.

    2) Use authorization_code to aquire Okta identity token and access token.

    3) Retrieve Okta public key and verify id_token JWT and nonce.

    4) If verified, return the users email for use in our own JWT.

    Reference for '/authorize' response headers and params: https://developer.okta.com/docs/reference/api/oidc/#response-properties
    """

    if "error" in request_params:
        logger.warn(request_params)
        if request_params["error"] == "access_denied":
            raise ForbiddenRequest("User not assigned app in Okta")
        else:
            raise UnauthorizedRequest("Error in okta response")

    if "code" not in request_params or request_params["code"] == "":
        logger.warn(request_params)
        raise UnauthorizedRequest("No code in okta response")

    if (
        "cookie" not in request_headers
        or "NONCE" not in request_headers["cookie"][0]["value"]
    ):
        raise UnauthorizedRequest("Missing cookie in okta response")

    id_token, access_token = get_tokens(request_params["code"])

    okta_public_key = get_okta_public_key(id_token)

    decoded_id = jwt.decode(
        id_token,
        okta_public_key,
        audience=okta_config["AUTH_REQUEST"]["client_id"],
        issuer=okta_config["BASE_URL"],
        access_token=access_token,
        options={"verify_sub": False},
    )

    validate_nonce(
        decoded_id["nonce"],
        BaseCookie(request_headers["cookie"][0]["value"])["NONCE"].value,
    )

    return decoded_id["email"]


def verify_existing_session(request_headers: HttpHeaders, request_uri: str):
    """
    Verify our JWT in the case that a user request has an existing session token.
    """
    options = {
        "verify_aud": True,
        "verify_iat": False,
        "verify_exp": True,
        "verify_nbf": False,
        "verify_iss": False,
        "verify_sub": False,
        "verify_jti": False,
        "leeway": 0,
    }
    cookie: Morsel = BaseCookie(request_headers["cookie"][0]["value"])["TOKEN"]

    decoded_token = jwt.decode(
        cookie.value,
        okta_config["JWT_KEY"],
        "HS512",
        audience=okta_config["DOMAIN_NAME"],
        options=options,
    )

    logger.info(f"User {decoded_token['email']} accessed {request_uri}")


def get_nonce_and_hash() -> Tuple[str, str]:
    """
    Get a secure random nonce and a hmac of that nonce
    """
    nonce: str = secrets.token_hex(32)
    nonce_hash: str = hmac.HMAC(
        bytes.fromhex(nonce), digestmod=hashlib.sha256
    ).hexdigest()
    return nonce, nonce_hash


def start_new_session(request_uri: str) -> HttpResponse:
    """
    Provide redirect body for okta authentication.

    Removes 'TOKEN' cookie if its present to nullify any old sessions client side.

    Creates 'NONCE' cookie with 'nonce_hash' as its value so the nonce that is sent to okta can be confirmed later.

    Request details https://developer.okta.com/docs/reference/api/oidc/#authorize
    """
    nonce, nonce_hash = get_nonce_and_hash()
    okta_config["AUTH_REQUEST"]["nonce"] = nonce
    okta_config["AUTH_REQUEST"]["state"] = request_uri

    # Set Nonce Cookie
    nonce_cookie: Morsel = Morsel()
    nonce_cookie.set("NONCE", nonce_hash, nonce_hash)
    nonce_cookie["path"] = "/"
    nonce_cookie["httponly"] = "true"
    nonce_cookie["secure"] = "true"
    return {
        "status": "302",
        "statusDescription": "Found",
        "body": "Redirecting to OKTA",
        "headers": {
            "location": [
                {
                    "key": "Location",
                    "value": f"{discovery_document['authorization_endpoint']}?{urllib.parse.urlencode(okta_config['AUTH_REQUEST'], doseq=True)}",
                }
            ],
            "set-cookie": [
                {"key": "Set-Cookie", "value": REMOVE_TOKEN_COOKIE},
                {"key": "Set-Cookie", "value": nonce_cookie.OutputString()},
            ],
        },
    }


def authenticate(event: Dict[str, Any]) -> HttpResponse:
    """
    This function handles one of 3 scenarios:

        1) If the user request is a callback from hitting the '/authorize' endpoint verify
           verify the new session information and if it checks out redirect to the protected site.
        2) If the user has an existing session cookie for this app verify it. If it is expired start a
           start a new session. If it has any other error throw a 401. If it passes all checks allow
           the user to view the site.
        3) If the user request is not a call back and doesn't have an existing session
           redirect to the Okta endpoint to start a new session.

    Reference for 'event' layout: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html
    """

    request: HttpRequest = event["Records"][0]["cf"]["request"]
    request_headers: HttpHeaders = request["headers"]
    request_params: HttpParams = {
        k: v[0] for k, v in urllib.parse.parse_qs(request["querystring"]).items()
    }
    request_uri: str = request["uri"]

    try:
        # Handle '/authorize' callback
        if request_uri.startswith(okta_config["CALLBACK_PATH"]):

            user_email = verify_new_session(request_headers, request_params)

            return redirect_to_site(request_params["state"], user_email)

        # Handle existing session
        elif (
            "cookie" in request_headers
            and "TOKEN" in request_headers["cookie"][0]["value"]
        ):

            verify_existing_session(request_headers, request_uri)

            return request

        # Handle new session
        else:
            return start_new_session(request_uri)

    except ExpiredSignatureError as e:
        logger.warn("token expired, redirecting to Okta")
        return start_new_session(request_uri)

    except JWTClaimsError as e:
        logger.warn(e)
        return UNAUTHORIZED_RESPONSE

    except JWTError as e:
        logger.warn(e)
        return UNAUTHORIZED_RESPONSE

    except UnauthorizedRequest as e:
        logger.warn(e)
        return UNAUTHORIZED_RESPONSE

    except ForbiddenRequest as e:
        logger.warn(e)
        return FORBIDDEN_RESPONSE


def get_global_configs():
    global okta_config
    global discovery_document
    global jwks

    if okta_config == {}:
        # Kind of hacky way to store what would normally be a enviroment variable
        # because lambda@edge can't use enviroment variables.
        with open("okta-key.txt") as f:
            okta_config_path = f.read().strip()

        response = secrets_client.get_secret_value(SecretId=okta_config_path)

        okta_config = json.loads(response["SecretString"])

        discovery_document = requests.get(okta_config["DISCOVERY_DOCUMENT"]).json()

        jwks = requests.get(discovery_document["jwks_uri"]).json()


def lambda_handler(event, context):
    try:
        get_global_configs()
        return authenticate(event)
    except Exception as e:
        logger.error(e)
        return INTERNAL_SERVER_ERROR
