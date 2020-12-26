import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify
from sptfy.errors import SptfyOAuthRedirect


def test_web_backend_auth_should_throw_exception_if_no_token_cached(
    sptfy_environment,
    token_file_cache
):
    track_id = 'some-track-id'

    credentials = oauth.ClientCredentials.from_env_variables() 
    # Given: A web backend strategy is chosen and an empty cache
    strategy = oauth.WebBackendAuth()
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
    strategy = oauth.WebBackendAuth()
    manager = oauth.AuthorizationCodeFlow(credentials, file_cache_with_token, strategy)
    sptfy = Spotify(oauth_manager=manager)

    # When: trying to hit an API endpoint
    response = sptfy.tracks.get(track_id)

    # Then: the endpoint should be hit
    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Curse'}
