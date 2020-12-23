
import pytest
import responses

import sptfy.oauth as oauth
from sptfy.sync import Spotify


@pytest.fixture
def token_file_cache(tmp_path):
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
    response = sptfy.tracks.get(track_id=track_id, transform=retrieve_name)

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
