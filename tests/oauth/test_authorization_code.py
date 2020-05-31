import json

import pytest
import responses

import sptfy.oauth as oauth


@pytest.fixture()
def token_with_refresh():
    token = oauth.OAuthToken(
        access_token='random-token-from-server',
        scope=['foo', 'bar'],
        expires_in=3600,
        token_type='Bearer',
        refresh_token='refresh-token-from-server',
    )
    return token


def test_oauth_token_file_cache_save_to_file(tmp_path):
    # GIVEN: An oauth token
    token = oauth.OAuthToken(
        access_token='some-random-token',
        token_type='Bearer',
        expires_in=3600,
        scope=['foo', 'bar']
    )
    # and an empty file
    cache_file = tmp_path / '.cache'
    cache = oauth.FileCache(cache_file)
    # WHEN: FileCache.save_token is called
    cache.save_token(token)

    # THEN: the contents of the token should be saved to file
    token_dict = json.loads(cache_file.read_text())
    oauth_token = oauth.OAuthToken.from_json(token_dict)
    assert oauth_token == token


def test_oauth_token_file_cache_restore(tmp_path):
    # GIVEN: An oauth token
    token = {
        'access_token': 'another-random-token',
        'token_type': 'Bearer',
        'expires_in': 3600,
        'scope': 'foo bar'
    }
    # and a cache file with a loaded token
    cache_path = tmp_path / '.cache'
    token_str = json.dumps(token)
    with cache_path.open('w') as cache_file:
        cache_file.write(token_str)

    cache = oauth.FileCache(cache_path)

    # WHEN: FileCache.load_token is called
    loaded_token = cache.load_token()

    # THEN: the token should be loaded to memory
    assert loaded_token == oauth.OAuthToken.from_json(token)


def test_oauth_token_file_cache_returns_none_on_error(tmp_path):
    # GIVEN: a nonexistent file
    cache_path = tmp_path / '.cache'

    cache = oauth.FileCache(cache_path)

    loaded_token = cache.load_token()

    # THEN: no token is returned
    assert loaded_token is None


@responses.activate
def test_oauth_authorization_code_refresh_token(token_with_refresh, sptfy_environment):
    # GIVEN: An oauth.AuthorizationCodeFlow initialized with credentials
    # and a oauth token with a refresh token
    client_id, client_secret, redirect_uri = sptfy_environment
    credentials = oauth.ClientCredentials(
        client_id,
        client_secret,
        redirect_uri
    )

    refreshed_token = {
        'access_token': 'new-token',
        'token_type': 'Bearer',
        'scope': 'foo bar',
        'expires_in': 3600,
    }

    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=refreshed_token,
        status=200,
    )

    auth_flow = oauth.AuthorizationCodeFlow(credentials)

    # WHEN: _refresh_token is called
    new_token = auth_flow._refresh_token(token_with_refresh)

    # THEN: The new token have the same refresh_token
    assert new_token.refresh_token == token_with_refresh.refresh_token
    # and same scope
    assert new_token.scope == token_with_refresh.scope
    # but different access token
    assert new_token.access_token == refreshed_token['access_token']


@responses.activate
def test_authorization_code_sends_payload_refresh_endpoint(token_with_refresh, sptfy_environment):
    client_id, client_secret, redirect_uri = sptfy_environment
    credentials = oauth.ClientCredentials(
        client_id,
        client_secret,
        redirect_uri
    )

    refreshed_token = {
        'access_token': 'new-token',
        'token_type': 'Bearer',
        'scope': 'foo bar',
        'expires_in': 3600,
    }

    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=refreshed_token,
        status=200,
    )

    auth_flow = oauth.AuthorizationCodeFlow(credentials)
    # WHEN: _refresh_token is called
    auth_flow._refresh_token(token_with_refresh)

    auth_header = credentials._authorization_header()
    request_sent = responses.calls[0].request
    # THEN: the authentication header should be created
    assert request_sent.headers['Authorization'] == auth_header['Authorization']
    # and the refresh token should be sent in the payload
    assert token_with_refresh.refresh_token in request_sent.body


@responses.activate
def test_oauth_authorization_code_refresh_token_not_200(token_with_refresh, sptfy_environment):
    # GIVEN: An oauth.AuthorizationCodeFlow initialized with credentials
    # and a oauth token with a refresh token
    client_id, client_secret, redirect_uri = sptfy_environment
    credentials = oauth.ClientCredentials(
        client_id,
        client_secret,
        redirect_uri
    )

    # and a broken endpoint
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json={'error': 'not found'},
        status=404,
    )

    auth_flow = oauth.AuthorizationCodeFlow(credentials)

    # WHEN: _refresh_token is called
    # THEN: it should raise an exception
    with pytest.raises(oauth.SptfyOAuthError):
        auth_flow._refresh_token(token_with_refresh)

