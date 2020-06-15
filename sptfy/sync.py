import os
import copy
from urllib.parse import urlencode, quote
from typing import Dict, Callable, Optional, Union, List, Any, overload

import requests

import sptfy.oauth as oauth
from sptfy.types import JsonDict


# Gave up on type hints


TRANSFORMER_CACHE = {}


def transform(endpoint: str):
    def decorator_stub(func):
        TRANSFORMER_CACHE[endpoint] = func
        return func
    return decorator_stub


# A transform example
def get_music_names(json: JsonDict) -> List[str]:
    return [item['name'] for item in json['tracks']['items']]


# Registered transform example:
# Registering the transform function will automatically
# run it when the function it transforms is called.
@transform('tracks.search')
def get_music_ids(json: JsonDict) -> List[str]:
    return [item['id'] for item in json['tracks']['items']]


class RequestConfig:
    def __init__(self, url, headers: Dict[str, str]):
        self.url = url
        self.headers = headers


class TracksEndpoint:
    BASE_URL = 'https://api.spotify.com/v1/tracks'

    def __init__(self, oauth_manager) -> None:
        self.oauth_manager = oauth_manager

    def _auth_header(self) -> Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorization': f'Bearer {token.access_token}'}

    def get(self, track_id: str) -> JsonDict:
        headers = self._auth_header()

        full_url = f"{self.BASE_URL}/{track_id}"

        response = requests.get(
            full_url,
            headers=headers,
        )

        if response.status_code != 200:
            raise Exception(f'Error downloading tracks: {response.reason}')

        return response.json()

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
            raise Exception(f'Error downloading tracks: {response.reason}')

        json_response: JsonDict = response.json()
        if transform:
            return transform(json_response)

        cached_transform = TRANSFORMER_CACHE.get('tracks.search')
        if cached_transform:
            return cached_transform(json_response)

        return json_response


class Spotify:
    BASE_URL = 'https://api.spotify.com/v1'

    def __init__(self, oauth_manager=None):
        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

        self._tracks = TracksEndpoint(self.oauth_manager)

    @property
    def tracks(self) -> TracksEndpoint:
        return self._tracks


if __name__ == '__main__':
    import pprint

    spfy = Spotify()
    
    # untransformed query
    json_track = spfy.tracks.search('No Weight')
    print('untransformed:')
    pprint.pprint(json_track)

    # Passing the transformer as a paremeter
    items = spfy.tracks.search('No Weight', transform=get_music_names)
    print('all items')
    for item in items:
        pprint.pprint(item)

