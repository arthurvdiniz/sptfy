import functools
import asyncio

import requests

import sptfy.oauth as oauth


def retrieve_token(
    authorization_code: str, 
    credentials 
):
    auth_header = credentials._authorization_header()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        **auth_header,
    }

    payload = {
        'redirect_uri': credentials.redirect_uri,
        'scope': ' '.join(credentials.scope),
        'code': authorization_code,
        'grant_type': 'authorization_code'
    }

    response = requests.post(
        oauth.OAUTH_TOKEN_ENDPOINT,
        data=payload,
        headers=headers,
    )

    if response.status_code != 200:
        error_response = response.json()
        raise oauth.SptfyOAuthError(
            (f"error: {error_response['error']}"
             f"description: {error_response['error_description']}"),
            error=error_response['error'],
            error_description=error_response['error_description']
        )

    return oauth.OAuthToken.created_now(response.json())


async def run_async(func, *args, **kwargs):
    """
    Offloads a synchronous function to a background thread.

    Only works with IO bound tasks.
    """
    loop = asyncio.get_event_loop()
    complete_func = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(None, complete_func)

