import os
import functools
import typing as t
from urllib.parse import urlencode, quote

import requests

from sptfy.types import JsonDict
from sptfy.errors import SptfyApiError


def _with_transformer(endpoint: str):
    """
    Applies a transform to the API json result, if one is specified.

    Avoids duplication of code in all endpoints.
    """
    def apply_transform(method):
        @functools.wraps(method)
        def call_endpoint_method(self, *args, transformer=None, **kwargs):
            json_response = method(self, *args, **kwargs)

            if transformer:
                return transformer(json_response)

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

    def _auth_header(self) -> t.Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorization': f'Bearer {token.access_token}'}

    @_with_transformer('tracks.get')
    def get(self, track_id: str) -> JsonDict:
        headers = self._auth_header()

        full_url = f"{self.BASE_URL}/{track_id}"

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error downloading tracks: {response.reason}')

        return response.json()

    @_with_transformer('tracks.search')
    def search(self, search_term: str) -> JsonDict:
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
            raise SptfyApiError(f"Error searching tracks: {response.reason}")

        return response.json()

    @_with_transformer('tracks.audio_features')
    def audio_features(self, track_id: str):
        base_url = os.path.dirname(self.BASE_URL)
        full_url = f"{base_url}/audio-features/{track_id}"
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error getting track features: {response.reason}')

        return response.json()



    @_with_transformer('tracks.audio_analysis')
    def audio_analysis(self, track_id: str):
        base_url = os.path.dirname(self.BASE_URL)
        full_url = f"{base_url}/audio-analysis/{track_id}"
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error getting track analysis: {response.reason}')

        return response.json()


class PlaylistEndpoint:
    BASE_URL = 'https://api.spotify.com/v1/playlists'

    def __init__(self, oauth_manager, transformer_cache):
        self.oauth_manager = oauth_manager
        self.transformer_cache = transformer_cache

    def _auth_header(self) -> t.Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorizaiton': f'Bearer {token.access_token}'}

    @_with_transformer('playlists.get')
    def get(self, playlist_id: str):
        """
        Retrieves playlist information from a given playlist ID.
        """
        headers = self._auth_header()
        full_url = f"{self.BASE_URL}/{playlist_id}"

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error downloading playlist: {response.reason}')

        return response.json()

    @_with_transformer('playlists.search')
    def search(self, search_term: str):
        top_url = os.path.dirname(self.BASE_URL)
        search_url = f"{top_url}/search"

        query = {
            'q': quote(search_term),
            'type': 'playlist'
        }

        params = urlencode(query)
        full_url = f'{search_url}?{params}'
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error searching for playlists: {response.reason}')

        return response.json()

    def create(
        self, 
        playlist_name: str, 
        songs: t.Optional[t.List[str]] = None, 
        public: bool = False,
        collaborative: bool = False
    ):
        headers = self._auth_header()
        base_url = os.path.dirname(self.BASE_URL)

        user_info = requests.get(
            f"{base_url}/me",
            headers=headers
        )

        if user_info.status_code != 200:
            raise SptfyApiError(f'Error retrieving user id: {user_info.reason}')

        user_json = user_info.json()
        user_id = user_json['id']

        full_url = f"{base_url}/users/{user_id}/playlists"
        post_data = {
            'name': playlist_name,
            'public': public,
            'collaborative': collaborative
        }
        response = requests.post(
            full_url,
            data=post_data
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error creating playlist: {response.reason}')

        if songs:
            json_response = response.json()
            playlist_id = json_response['id']
            self.add_to(playlist_id, songs=songs)


    def add_to(
        self, 
        playlist_id: str, 
        songs: t.List[str],
        position: t.Optional[int] = None
    ):
        headers = self._auth_header()
        headers['Content-Type'] = 'application/json'
        full_url = f"{self.BASE_URL}/{playlist_id}/tracks"

        post_data : t.Dict[str, t.Any] = {
            'uris': songs
        }
        if position:
            post_data['position'] = position

        response = requests.post(
            full_url,
            headers=headers,
            data=post_data
        )

        if response.status_code != 200:
            raise SptfyApiError(f"Error adding items to playlist: {response.reason}")

    def remove_from(self, playlist_name: str, songs: t.List[str]):
        pass

    @_with_transformer('playlists.from_user')
    def from_user(self , user_id: str):
        pass


class ArtistsEndpoint:
    BASE_URL = 'https://api.spotify.com/v1/artists'

    def __init__(self, oauth_manager, transformer_cache):
        self.oauth_manager = oauth_manager
        self.transformer_cache = transformer_cache

    def _auth_header(self) -> t.Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorizaiton': f'Bearer {token.access_token}'}

    @_with_transformer('artists.get')
    def get(self, artist_id: str):
        headers = self._auth_header()
        full_url = f"{self.BASE_URL}/{artist_id}"

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error downloading artists: {response.reason}')

        return response.json()

    @_with_transformer('artists.search')
    def search(self, search_term: str):
        top_url = os.path.dirname(self.BASE_URL)
        search_url = f"{top_url}/search"

        query = {
            'q': quote(search_term),
            'type': 'artist'
        }

        params = urlencode(query)
        full_url = f'{search_url}?{params}'
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error searching for artists: {response.reason}')

        return response.json()


class AlbumsEndpoint:
    BASE_URL = 'https://api.spotify.com/v1/albums'

    def __init__(self, oauth_manager, transformer_cache):
        self.oauth_manager = oauth_manager
        self.transformer_cache = transformer_cache

    def _auth_header(self) -> t.Dict[str, str]:
        token = self.oauth_manager.get_access_token()
        return {'Authorizaiton': f'Bearer {token.access_token}'}

    @_with_transformer('albums.get')
    def get(self, album_id: str):
        headers = self._auth_header()
        full_url = f"{self.BASE_URL}/{album_id}"

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error downloading album: {response.reason}')

        return response.json()

    @_with_transformer('albums.search')
    def search(self, search_term: str):
        top_url = os.path.dirname(self.BASE_URL)
        search_url = f"{top_url}/search"

        query = {
            'q': quote(search_term),
            'type': 'album'
        }

        params = urlencode(query)
        full_url = f'{search_url}?{params}'
        headers = self._auth_header()

        response = requests.get(
            full_url,
            headers=headers
        )

        if response.status_code != 200:
            raise SptfyApiError(f'Error searching for albums: {response.reason}')

        return response.json()
