import pytest
import responses

import sptfy.oauth as oauth
from sptfy.sync import Spotify
from sptfy.errors import SptfyOAuthRedirect

@pytest.fixture
def token_file_cache(tmp_path):
    """
    Creates and empty file based token cache
    in a temporary file.
    """
    
    cache_file = tmp_path / '.cache'
    cache = oauth.FileCache(cache_file)
    return cache

@pytest.fixture
def file_cache_with_token(token_file_cache):
    token = oauth.OAuthToken(
        access_token='some-random-token',
        token_type='Bearer',
        expires_in=3600,
        scope=['foo', 'bar']
    )

    token_file_cache.save_token(token)
    return token_file_cache


def test_web_backend_auth_should_throw_exception_if_no_token_cached(
    sptfy_environment,
    token_file_cache
):
    track_id = 'some-track-id'

    # I dislike that the user needs to specify the same cache
    # for both the auth strategy and manager

    credentials = oauth.ClientCredentials.from_env_variables() 
    # Given: A web backend strategy is chosen and an empty cache
    strategy = oauth.WebBackendAuth(credentials, token_file_cache)
    manager = oauth.AuthorizationCodeFlow(credentials, token_file_cache, strategy)
    sptfy = Spotify(oauth_manager=manager)

    # When: trying to hit an API endpoint
    # Then: it should raise an error
    with pytest.raises(SptfyOAuthRedirect):
        sptfy.tracks.get(track_id)

@responses.activate
def test_web_backend_auth_shouldnt_throw_exception_if_token_is_available(
    sptfy_environment,
    file_cache_with_token
):
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Curse'}},
        status=200,
    )


    credentials = oauth.ClientCredentials.from_env_variables() 
    # Given: A web backend strategy is chosen and full cache
    strategy = oauth.WebBackendAuth(credentials, file_cache_with_token)
    manager = oauth.AuthorizationCodeFlow(credentials, file_cache_with_token, strategy)
    sptfy = Spotify(oauth_manager=manager)

    # When: trying to hit an API endpoint
    response = sptfy.tracks.get(track_id)

    # Then: the endpoint should be hit
    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Curse'}
