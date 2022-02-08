""" This lambda function checks """

from typing import Dict, Union

import requests
from jose import jwt
from jose.exceptions import JWTError, JWSError


# Config requires hard coding REGION, USERPOOLID and CLIENTID,
# since lambda@edge does not support env variables (state Feb.2022)
REGION = ""
USERPOOLID = ""
CLIENTID = ""
REDIRECTURI = ""

# Add more header options here when required
HEADERS = {
    "cache-control:no-cache": [{"key": "Cache-Control", "value": "no-cache"}],
    "content-type:text/html": [{"key": "Content-Type", "value": "text/html"}],
    "location:redirect_uri": [{"key": "Location", "value": REDIRECTURI}],
}

# Have some default responses
NOT_AUTHORIZED_401 = {
    "status": "401",
    "statusDescription": "Unauthorized",
    "headers": {
        "cache-control": HEADERS["cache-control:no-cache"],
        "content-type": HEADERS["content-type:text/html"],
    },
    "body": "Sorry, not with this token.",
}
REDIRECT_302 = {
    "status": "302",
    "statusDescription": "Found",
    "headers": {"location": HEADERS["location:redirect_uri"]},
}

# On failure return the following response
DEFAULT_RESPONE = REDIRECT_302

# List of user_info in access_token to check
required_user_info = (
    "sub",
    "cognito:groups",  # only required when working with groups
    "token_use",
    "scope",
    "auth_time",
    "iss",
    "exp",
    "client_id",
    "username",
)


class TokenVerificationException(Exception):
    """Raised when token verification fails, taken from https://github.com/pvizeli/pycognito."""


class TokenVerifier:
    """Simpler version of https://github.com/pvizeli/pycognito."""

    def __init__(
        self, user_pool_id: str, client_id: str, pool_region: str, pool_jwk=None
    ):
        self.user_pool_id = user_pool_id
        self.client_id = client_id
        self.pool_region = pool_region
        self.pool_jwk = pool_jwk

    @property
    def user_pool_url(self):
        """Construct the user pools jwks url (details at: https://github.com/pvizeli/pycognito)"""
        return (
            f"https://cognito-idp.{self.pool_region}.amazonaws.com/{self.user_pool_id}"
        )

    @property
    def user_pool_jwks_url(self) -> str:
        """Construct the user pools jwks url (details at: https://github.com/pvizeli/pycognito)"""
        return f"{self.user_pool_url}/.well-known/jwks.json"

    def get_keys(self) -> Dict:
        """Get public keys from cognitos jwks (details at: https://github.com/pvizeli/pycognito)"""
        if self.pool_jwk:
            return self.pool_jwk
        # If it is not there use the requests library to get it
        else:
            self.pool_jwk = requests.get(self.user_pool_jwks_url).json()
        return self.pool_jwk

    def get_key(self, kid) -> str:
        """Get key from pools jwk json 'kids' (details at: https://github.com/pvizeli/pycognito)"""
        keys = self.get_keys().get("keys")
        key = list(filter(lambda x: x.get("kid") == kid, keys))
        return key[0]

    def verify_token(
        self, token: str, id_name: str = "access_token", token_use: str = "access"
    ) -> Dict:
        """Verify token using jwt (details at: https://github.com/pvizeli/pycognito)"""
        kid = jwt.get_unverified_header(token).get("kid")
        hmac_key = self.get_key(kid)
        try:
            verified = jwt.decode(
                token,
                hmac_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.user_pool_url,
                options={
                    "require_aud": token_use != "access",
                    "require_iss": True,
                    "require_exp": True,
                },
            )
        except JWTError:
            raise TokenVerificationException(
                f"Your {id_name!r} token could not be verified."
            ) from None

        token_use_verified = verified.get("token_use") == token_use
        if not token_use_verified:
            raise TokenVerificationException(
                f"Your {id_name!r} token use ({token_use!r}) could not be verified."
            )

        return verified


def check_headers(headers: Dict) -> Union[str, bool]:
    """Check header content for 'Authorization: Bearer <token>' in request
    authorization (key, values).
    """
    if "authorization" not in headers.keys():
        return False
    # Needs only one auth header. Change this it when required.
    if not len(headers["authorization"]) == 1:
        return False
    token_string = ""
    auth_values = headers["authorization"][0]["value"].split()
    if not (
        len(auth_values) == 2 and auth_values[0].lower() == "bearer" and auth_values[1]
    ):
        return False
    token_string = auth_values[1]
    return token_string


def check_token_access(access_token: Dict) -> bool:
    """Check token contents (user_info and expectation)"""
    # Check if all required user_info is present in token
    if not all(
        [
            (user_info in access_token.keys() and access_token[user_info] is not None)
            for user_info in required_user_info
        ]
    ):
        return False
    # Check if the token content matches expectation
    if not (
        access_token["token_use"] == "access"
        and access_token["iss"]
        == f"https://cognito-idp.{REGION}.amazonaws.com/{USERPOOLID}"
        and access_token["client_id"] == CLIENTID
    ):
        return False
    return True


def modify_request(cloud_front_request: Dict) -> Dict:
    """Remove header from viewer request for cloudfronts origin request"""
    del cloud_front_request["headers"]["authorization"]
    return cloud_front_request


def lambda_handler(event, context):
    """Lambda handler"""
    cf_request = event["Records"][0]["cf"]["request"]
    headers = cf_request["headers"]
    header_check = check_headers(headers)
    if isinstance(header_check, bool) and header_check is False:
        print("An error occured (invalid header):")
        return DEFAULT_RESPONE
    token_string = header_check
    token_verifier = TokenVerifier(USERPOOLID, CLIENTID, REGION)
    decoded_token = {}
    try:
        decoded_token = token_verifier.verify_token(
            token_string, "access_token", "access"
        )
    except (TokenVerificationException, JWTError, JWSError) as e:
        print("An error occured (token verfication failed):")
        print(e)
        return DEFAULT_RESPONE
    token_check = check_token_access(decoded_token)
    if token_check is False:
        print("An error occured (unauthorized token content):")
        return DEFAULT_RESPONE
    response = modify_request(cf_request)
    print(response)
    return response
