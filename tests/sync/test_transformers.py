import pytest
import responses

import sptfy.oauth as oauth
from sptfy.sync import Spotify


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
def test_spotify_disable_transformers_should_reset_transformers_temporarily(
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

    sptfy = Spotify(oauth_manager=oauth_manager)

    # Given: a transformer that retrieves the track's name
    @sptfy.transformer('tracks.get')
    def retrieve_name(response):
        return response['track']['name']

    # When: trying to retrieve a track with a specific transformer
    response = sptfy.tracks.get(track_id=track_id, transformer=retrieve_name)

    # Then: the result should be the given by the transformer 
    # instead of the json
    assert response == 'Labyrinth'

    # When: the disable_transformers context manager is used
    with sptfy.disable_transformers():
        response = sptfy.tracks.get(track_id)

    # Then: the response should not be transformed
    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Disco'}

    # Makes sure the context manager resets the transformers to
    # the way it was before

    # When: retrieving data after the context manager finished
    response = sptfy.tracks.get(track_id)

    # Then: the result should be transformed again
    assert response == 'Labyrinth'
