from urllib.parse import urlencode, quote 

import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify


@pytest.fixture
def token_file_cache(tmp_path):
    """
    Creates a token cache with a fake OAuth token,
    so that the tests avoid authenticating with the
    API.
    """
    token = oauth.OAuthToken(
        access_token='some-random-token',
        token_type='Bearer',
        expires_in=3600,
        scope=['foo', 'bar']
    )

    cache_file = tmp_path / '.cache'
    cache = oauth.FileCache(cache_file)
    cache.save_token(token)

    return cache


@responses.activate
def test_spotify_tracks_get_should_call_endpoint(sptfy_environment, token_file_cache):
    # Given: An user specified track id
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)

    # When: trying to retrieve a track
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.get(track_id=track_id)

    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Disco'} 


@responses.activate
def test_spotify_tracks_get_should_accept_transform(sptfy_environment, token_file_cache):
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)

    # Given: a transformer that retrieves the track's name
    def retrieve_name(response):
        return response['track']['name']

    # When: trying to retrieve a track with a specific transformer
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.get(track_id=track_id, transformer=retrieve_name)

    # Then: the result should be the given by the transformer 
    # instead of the json
    assert response == 'Labyrinth'


@responses.activate
def test_spotify_tracks_get_should_accept_cached_transform(
    sptfy_environment,
    token_file_cache
):
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)

    # Given: a transformer that retrieves the track's name, 
    # that its cached on the Spotify object.
    sptfy = Spotify(oauth_manager=oauth_manager)
    
    @sptfy.transformer('tracks.get')
    def retrieve_name(response):
        return response['track']['name']

    # When: trying to retrieve a track with a specific transformer
    response = sptfy.tracks.get(track_id=track_id)

    assert response == 'Labyrinth'


def test_tracks_get_should_raise_exception_if_not_200(
    sptfy_environment,
    token_file_cache
):
    # Given: An inexistent track object (i.e. 404)
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        status=404,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)
    sptfy = Spotify(oauth_manager=oauth_manager)

    # When: getting a inexistent track
    # Then: an exception should be raised
    with pytest.raises(Exception):
        sptfy.tracks.get(track_id)


@responses.activate
def test_tracks_search_should_hit_correct_endpoint(
    sptfy_environment,
    token_file_cache
):
    # Given: An inexistent track object (i.e. 404)
    track_name = 'The Lost Chord'
    search_query = {
        'q': quote(track_name), 
        'type': 'track',
    }
    params = urlencode(search_query)

    json_response = {
        'tracks': {
            'items': ['track-object-1', 'track-object-2', 'track-object-3']
        }
    }
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/search?{params}',
        json=json_response,
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)

    sptfy = Spotify(oauth_manager=oauth_manager)

    # When: searching for a track
    response = sptfy.tracks.search(track_name)

    # Then: it should receive a list of track objects 
    # that matches the query
    assert len(response['tracks']['items']) == 3


@responses.activate
def test_tracks_search_should_hit_correct_endpoint(
    sptfy_environment,
    token_file_cache
):
    track_name = 'Lets go to the mall'
    search_query = {
        'q': quote(track_name), 
        'type': 'track',
    }
    params = urlencode(search_query)

    # Given: An api problem
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/search?{params}',
        status=500,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=token_file_cache)

    sptfy = Spotify(oauth_manager=oauth_manager)

    # When: server error occurs
    # Then: it should raise an exception
    with pytest.raises(Exception):
        sptfy.tracks.search(track_name)


