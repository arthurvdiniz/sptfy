"""
This holds some tests for endpoints that have similar methods.

Some examples are the search() and get() methods which are present
in the tracks, albums, artists and playlists endpoints.
"""
import re
from urllib.parse import urlencode, quote

import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify
from sptfy.errors import SptfyApiError


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

# Testing errors for different endpoints
# Works only if the method makes a single http request
errors_params = [
    ("tracks", "get", "GET", {"track_id": "track-id"}, "Error requesting track"),
    ("playlists", "get", "GET", {"playlist_id": "playlist-id"}, "Error requesting playlist"),
    ("albums", "get", "GET", {"album_id": "album-id"}, "Error requesting album"),
    ("artists", "get", "GET", {"artist_id": "artist-id"}, "Error requesting artist"),
    ("tracks", "search", "GET", {"search_term": "Simple Song"}, "Error searching track"),
    ("playlists", "search", "GET", {"search_term": "Best Songs"}, "Error searching playlist"),
    ("albums", "search", "GET", {"search_term": "Epoch"}, "Error searching album"),
    ("artists", "search", "GET", {"search_term": "Hiatus Kaiyote"}, "Error searching artist"),
    ("tracks", "audio_features", "GET", {"track_id": "track-id"}, "Error getting track features"),
    ("tracks", "audio_analysis", "GET", {"track_id": "track-id"}, "Error getting track analysis"),
    (
        "playlists", "add_to", "POST",
        { "playlist_id": "playlist-id", "songs": ["doesnt-matter-id"] }, 
        "Error adding items to playlist"
    ),
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
    sess = spot.session()

    # When: searching for a playlist
    end = getattr(sess, endpoint)
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
    sess = spot.session()
    end = getattr(sess, endpoint)
    get_func = getattr(end, 'get')
    response = get_func(item_id)

    assert response[singular_item_name] == {'name': 'Labyrinth', 'artist': 'Surf Disco'} 


@responses.activate
@pytest.mark.parametrize("endpoint,method,http_method,params,error_message", errors_params)
def test_endpoints_should_raise_exception_if_not_200(
    endpoint,
    method,
    http_method,
    params,
    error_message,
    sptfy_environment,
    file_cache_with_token
):
    # Given: An inexistent track object (i.e. 404)
    responses.add(
        http_method,
        re.compile('https://api.spotify.com/v1/.*'),
        status=404,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )
    spot = Spotify(oauth_manager=oauth_manager)
    sess = spot.session()

    # When: getting a inexistent track
    # Then: an exception should be raised
    with pytest.raises(SptfyApiError) as exc:
        end = getattr(sess, endpoint)
        method_func = getattr(end, method)
        method_func(**params)

    assert error_message in str(exc.value)


