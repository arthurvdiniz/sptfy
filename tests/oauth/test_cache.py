import re
import unittest.mock as mock

import responses

from sptfy.clients import Spotify
import sptfy.oauth as oauth


@responses.activate
def test_oauth_save_token_should_only_be_called_once_with_terminal_auth(
    sptfy_environment
):
    track_id = 'some-id'
    token = oauth.OAuthToken(
        access_token='some-random-token',
        token_type='Bearer',
        expires_in=3600,
        scope=['foo', 'bar']
    )

    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    # Given: An empty cache
    cache = mock.Mock()
    cache.load_token.return_value = None
    auth_strategy = mock.Mock()
    auth_strategy.authorize.return_value = token

    credentials = oauth.ClientCredentials.from_env_variables()
    manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=cache, 
        auth_strategy=auth_strategy
    )

    sptfy = Spotify(oauth_manager=manager)
    sess = sptfy.session()

    # When: calling any function 
    # (which will trigger authorization since cache is empty)
    sess.tracks.get(track_id)

    # Then: save_token should only be called once
    cache.save_token.assert_called_once_with(token)
