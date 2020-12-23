import os
import functools
from urllib.parse import urlencode, quote
from typing import Dict

import requests

import sptfy.oauth as oauth
from sptfy.types import JsonDict


def with_transformer(endpoint):
    """
    Applies a transform to the API json result, if one is specified.

    Avoids duplication of code in all endpoints.
    """
    def apply_transform(method):
        @functools.wraps(method)
        def call_endpoint_method(self, *args, transform=None, **kwargs):
            json_response = method(self, *args, **kwargs)

            if transform:
                return transform(json_response)

            cached_transform = self.transformer_cache.get(endpoint)
            if cached_transform:
                return cached_transform(json_response)

            return json_response
        return call_endpoint_method
    return apply_transform



class TracksEndpoint:
    BASE_URL = 'https://api.spotify.com/v1/tracks'

    def __init__(self, oauth_manager, transformer_cache) -> None:
        self.oauth_manager = oauth_manager
        self.transformer_cache = transformer_cache

    def _auth_header(self) -> Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorizaiton': f'Bearer {token.access_token}'}

    @with_transformer('tracks.get')
    def get(self, track_id: str) -> JsonDict:
        headers = self._auth_header()

        full_url = f"{self.BASE_URL}/{track_id}"

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise Exception(f'Error downloading tracks: {response.reason}')

        return response.json()

    @with_transformer('tracks.search')
    def search(self, search_term, transform=None):
        top_url = os.path.dirname(self.BASE_URL)
        search_url = f"{top_url}/search"

        query = {
            'q': quote(search_term),
            'type': 'track'
        }

        params = urlencode(query)
        full_url = f'{search_url}?{params}'
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise Exception(f"Error searching tracks: {response.reason}")

        return response.json()


class Spotify:
    """
    Represents an user session to the Spotify Web API.

    By default it uses the Authorization Code Flow, but it can 
    be changed by using the [oauth_manager] argument.
    """
    BASE_URL = 'https://api.spotify.com/v1'

    def __init__(self, oauth_manager=None):
        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

        self.transformer_cache = {}

        self.tracks = TracksEndpoint(self.oauth_manager, self.transformer_cache)

    def transformer(self, endpoint: str):
        """
        Registers a transformer to this Spotify session.

        Works similarly to Flask's @app.route() decorator.
        """
        def add_transform_to_cache(func):
            self.transformer_cache[endpoint] = func
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return add_transform_to_cache
