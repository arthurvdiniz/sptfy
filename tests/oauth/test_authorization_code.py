import json
import time
from urllib.parse import quote
from unittest.mock import Mock, patch, call

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


unmocked = time.time
def time_initial_values(values=None):
    if values is None:
        values = []
    iter_val = iter(values)

    def time_side_effect():
        try:
            return next(iter_val)
        except StopIteration:
            return unmocked()


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


@responses.activate
def test_oauth_authorization_code_request_access_token(sptfy_environment):
    # GIVEN: An authorization strategy which returns the code from the
    # authorize endpoint
    mock_strategy = Mock()
    client_id, client_secret, redirect_uri = sptfy_environment
    credentials = oauth.ClientCredentials(
        client_id,
        client_secret,
        redirect_uri
    )

    some_token = {
        'access_token': 'new-token',
        'token_type': 'Bearer',
        'scope': 'foo bar',
        'expires_in': 3600,
    }

    # the API returns correctly (200)
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token,
        status=200
    )

    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy
    )

    # WHEN: _request_access_token is called
    token = auth_flow._request_access_token()

    # THEN: the access_token should be returned
    assert token == oauth.OAuthToken.from_json(some_token)


@responses.activate
def test_oauth_authorization_code_request_access_token_correct_input(sptfy_environment):
    # GIVEN: an authorization strategy
    mock_strategy = Mock()
    mock_strategy.on_authorization_response.return_value = 'code-from-server'

    client_id, client_secret, redirect_uri = sptfy_environment
    credentials = oauth.ClientCredentials(
        client_id,
        client_secret,
        redirect_uri
    )

    some_token = {
        'access_token': 'new-token',
        'token_type': 'Bearer',
        'scope': 'foo bar',
        'expires_in': 3600,
    }

    # the API returns correctly (200)
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token,
        status=200
    )

    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy
    )
    
    # WHEN: request_access_token is called
    auth_flow._request_access_token()

    request_sent = responses.calls[0].request
    auth_header = credentials._authorization_header()
    # THEN: the authorization header should be present
    assert request_sent.headers['Authorization'] == auth_header['Authorization']
    # the payload should be constructed
    assert 'redirect_uri' in request_sent.body
    assert "code-from-server" in request_sent.body
    # the authorization strategy methods should be called
    assert mock_strategy.authorize.call_args == call(credentials)
    assert mock_strategy.on_authorization_response.called


@patch('sptfy.oauth.time.time')
def test_authorization_code_get_access_token_from_memory(mock_time, sptfy_environment):
    mock_time.return_value = 0
    credentials = oauth.ClientCredentials.from_env_variables()
    mock_strategy = Mock()
    some_token = oauth.OAuthToken(
        access_token='new-token',
        token_type='Bearer',
        scope=['foo', 'bar'],
        expires_in=3600,
    )

    # GIVEN: An AuthorizationCodeFlow with a non-expired token in memory
    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy
    )
    auth_flow._current_token = some_token

    # WHEN: get_access_token is called
    token = auth_flow.get_access_token()

    # THEN: the token should be returned from memory
    assert token == some_token


@patch('sptfy.oauth.AuthorizationCodeFlow._validate_token')
def test_authorization_code_loads_from_cache_if_not_in_memory(mock_validate_token, sptfy_environment):

    credentials = oauth.ClientCredentials.from_env_variables()
    mock_strategy = Mock()
    token_cache = Mock()
    some_token = oauth.OAuthToken(
        access_token='new-token',
        token_type='Bearer',
        scope=['foo', 'bar'],
        expires_in=3600,
    )

    # GIVEN: a token cache loaded with a token
    token_cache.load_token.return_value = some_token

    # And no token in memory
    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        token_cache=token_cache,
        auth_strategy=mock_strategy,
    )

    # WHEN: get_access_token is called
    auth_flow.get_access_token()

    # THEN: the token should be loaded from cache
    assert token_cache.load_token.called
    # it should be validated
    assert mock_validate_token.call_args == call(some_token)
    # the current token should be updated
    assert auth_flow._current_token == some_token



@responses.activate
def test_authorization_code_gets_token_from_api(sptfy_environment):
    credentials = oauth.ClientCredentials.from_env_variables()
    mock_strategy = Mock()
    mock_cache = Mock()
    # GIVEN: an empty cache and no token in memory
    mock_cache.load_token.return_value = None

    some_token = oauth.OAuthToken(
        access_token='new-token',
        token_type='Bearer',
        scope=['foo', 'bar'],
        expires_in=3600,
    )

    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy,
        token_cache=mock_cache,
    )

    # The response for the web api is the new token
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token.to_dict(),
        status=200
    )

    # WHEN: get_access_token is called
    token = auth_flow.get_access_token()

    request_sent = responses.calls[0].request
    # THEN: the token should come from the api
    assert token == some_token
    assert request_sent.headers['Content-Type'] == 'application/x-www-form-urlencoded'
    # and the token is saved in memory
    assert auth_flow._current_token == some_token


@responses.activate
@patch('sptfy.oauth.time.time')
def test_authorization_code_get_access_token_refreshs_if_expired(mock_time, sptfy_environment):
    mock_time.return_value = 100
    credentials = oauth.ClientCredentials.from_env_variables()
    mock_strategy = Mock()
    mock_cache = Mock()

    some_token = oauth.OAuthToken(
        access_token='new-token',
        token_type='Bearer',
        scope=['foo', 'bar'],
        expires_in=-1,  # expires the token
        refresh_token='refresh-me'
    )

    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy,
        token_cache=mock_cache,
    )
    auth_flow._current_token = some_token

    # The response for the web api is the new token
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token.to_dict(),
        status=200
    )

    # WHEN: get_access_token is called
    token = auth_flow.get_access_token()

    # THEN: the token should be refreshed
    request_sent = responses.calls[0].request
    assert 'refresh_token' in request_sent.body
    # the token should be returned from the api
    assert token == some_token


@responses.activate
def test_authorization_code_saves_if_its_new_token(sptfy_environment):
    credentials = oauth.ClientCredentials.from_env_variables()
    mock_strategy = Mock()
    # GIVEN: an empty cache and memory
    mock_cache = Mock()
    mock_cache.load_token.return_value = None

    some_token = oauth.OAuthToken(
        access_token='new-token',
        token_type='Bearer',
        scope=['foo', 'bar'],
        expires_in=-1,  # expires the token
        refresh_token='refresh-me'
    )

    auth_flow = oauth.AuthorizationCodeFlow(
        credentials,
        auth_strategy=mock_strategy,
        token_cache=mock_cache,
    )

    # a new token is returned from the api (either refreshed or new request)
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token.to_dict(),
        status=200
    )

    # WHEN: get_access_token is called
    auth_flow.get_access_token()

    # THEN: the new token is saved to cache
    assert mock_cache.save_token.call_args == call(some_token)
