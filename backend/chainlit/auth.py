import os
from datetime import datetime, timedelta
from typing import Any, Dict

import jwt
import requests
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from chainlit.config import config
from chainlit.data import get_data_layer
from chainlit.oauth_providers import get_configured_oauth_providers
from chainlit.user import User
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

reuseable_oauth = OAuth2PasswordBearer(tokenUrl="/login", auto_error=False)


def get_jwt_secret():
    return os.environ.get("CHAINLIT_AUTH_SECRET")


def ensure_jwt_secret():
    if require_login() and get_jwt_secret() is None:
        raise ValueError(
            "You must provide a JWT secret in the environment to use authentication. Run `chainlit create-secret` to generate one."
        )


def is_oauth_enabled():
    return config.code.oauth_callback and len(get_configured_oauth_providers()) > 0


def require_login():
    return (
        bool(os.environ.get("CHAINLIT_CUSTOM_AUTH"))
        or config.code.password_auth_callback is not None
        or config.code.header_auth_callback is not None
        or is_oauth_enabled()
    )


def get_configuration():
    return {
        "requireLogin": require_login(),
        "passwordAuth": config.code.password_auth_callback is not None,
        "headerAuth": config.code.header_auth_callback is not None,
        "oauthProviders": get_configured_oauth_providers()
        if is_oauth_enabled()
        else [],
    }


def create_jwt(data: User) -> str:
    to_encode = data.to_dict()  # type: Dict[str, Any]
    to_encode.update(
        {
            "exp": datetime.utcnow() + timedelta(minutes=60 * 24 * 15),  # 15 days
        }
    )
    encoded_jwt = jwt.encode(to_encode, get_jwt_secret(), algorithm="HS256")
    return encoded_jwt


async def authenticate_user(token: str = Depends(reuseable_oauth)):
    try:
        dict = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=["HS256"],
            options={"verify_signature": True},
        )
        del dict["exp"]
        user = User(**dict)
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    if data_layer := get_data_layer():
        try:
            persisted_user = await data_layer.get_user(user.identifier)
            if persisted_user == None:
                persisted_user = await data_layer.create_user(user)
        except Exception as e:
            return user

        return persisted_user
    else:
        return user


async def get_current_user(token: str = Depends(reuseable_oauth)):
    if not require_login():
        return None

    return await authenticate_user(token)



def base64url_decode(input):
    # Adds padding to the input before decoding
    rem = len(input) % 4
    if rem > 0:
        input += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input)


def construct_rsa_public_key(n, e):
    # Decode the base64url encoded values
    decoded_n = base64url_decode(n)
    decoded_e = base64url_decode(e)

    # Convert to integers
    int_n = int.from_bytes(decoded_n, byteorder='big')
    int_e = int.from_bytes(decoded_e, byteorder='big')

    # Construct RSA Public Key
    return rsa.RSAPublicNumbers(e=int_e, n=int_n).public_key(default_backend())


def get_rsa_public_key(jwks, kid):
    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
            return construct_rsa_public_key(key['n'], key['e'])
    raise Exception("Public key not found in JWKS")


def get_public_key(jwks_uri, kid):

    jwks_response = requests.get(jwks_uri)
    jwks = jwks_response.json()
    key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
    if not key:
        raise Exception("Public key not found in JWKS")
    return get_rsa_public_key(jwks, kid)


def validate_jwt(token, jwks_uri):
    unverified_header = jwt.get_unverified_header(token)
    public_key = get_public_key(jwks_uri, unverified_header['kid'])
    return public_key


def decode_jwt(token, public_key, audience, issuer):
    try:
        return jwt.decode(token, public_key, algorithms=["RS256"], audience=audience, issuer=issuer)
    except Exception as e:
        print(e)
        return None
