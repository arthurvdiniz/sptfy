"""
This holds some tests for endpoints that have similar methods.

Some examples are the search() and get() methods which are present
in the tracks, albums, artists and playlists endpoints.
"""
from urllib.parse import urlencode, quote
import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify


search_params = [
    ("playlists", "Best Of 2019"), 
    ("tracks", "Trust"),
    ("artists", "Gorillaz"),
    ("albums", "To Pimp A Butterfly"),
]


get_params = [
    ("tracks", "track-id"),
    ("playlists", "playlist-id"),
    ("albums", "album-id"),
    ("artists", "artist-id"),
]


@responses.activate
@pytest.mark.parametrize("endpoint,item_name", search_params)
def test_search_should_hit_correct_endpoint(
    endpoint,
    item_name,
    sptfy_environment,
    file_cache_with_token
):
    search_query = {
        'q': quote(item_name), 
        'type': endpoint[:-1],
    }
    params = urlencode(search_query)

    json_response = {
        endpoint: {
            'items': ['object-1', 'object-2', 'object-3']
        }
    }
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/search?{params}',
        json=json_response,
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    spot = Spotify(oauth_manager=manager)

    # When: searching for a playlist
    end = getattr(spot, endpoint)
    search_func = getattr(end, 'search')
    response = search_func(item_name)

    # Then: the response from the api should be correct
    assert len(response[endpoint]['items']) == 3

@responses.activate
@pytest.mark.parametrize("endpoint,item_id", get_params)
def test_spotify_get_should_call_endpoint(
    endpoint,
    item_id,
    sptfy_environment, 
    file_cache_with_token      # The cached token avoid trying to authenticate in tests
):
    singular_item_name = endpoint[:-1]
    # Given: An user specified item id
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/{endpoint}/{item_id}',
        json={ singular_item_name: {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # When: trying to retrieve a track
    spot = Spotify(oauth_manager=oauth_manager)
    end = getattr(spot, endpoint)
    get_func = getattr(end, 'get')
    response = get_func(item_id)

    assert response[singular_item_name] == {'name': 'Labyrinth', 'artist': 'Surf Disco'} 


