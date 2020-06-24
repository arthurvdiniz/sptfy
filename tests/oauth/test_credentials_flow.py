import time
import base64
from unittest.mock import patch

import pytest
import responses

import sptfy.oauth as oauth


def authorization_header(client_id, client_secret):
    credentials_header = f'{client_id}:{client_secret}'.encode(encoding='ascii')
    authorization_header = base64.b64encode(credentials_header)
    return {'Authorization': f"Basic {authorization_header.decode('ascii')}"}


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
    return time_side_effect


def test_oauth_client_credentials_flow_from_env(sptfy_environment):
    # GIVEN: Environment variables necessary for client credentials flow
    client_id, client_secret, redirect_uri = sptfy_environment

    # WHEN: client credentials flow is initialized with no parameters
    credentials_flow = oauth.ClientCredentialsFlow()

    # THEN: Credentials variables should be loaded from env variables
    assert credentials_flow.credentials.client_id == client_id
    assert credentials_flow.credentials.client_secret == client_secret
    # redirect_uri is not necessary for client credentials flow, but
    # it's still loaded if the variable is defined
    assert credentials_flow.credentials.redirect_uri == redirect_uri


@responses.activate
def test_oauth_client_credentials_request_token(sptfy_environment):
    # GIVEN: ClientCredentialsFlow object initialized with the client credentials
    client_id, client_secret, _ = sptfy_environment
    credentials = oauth.ClientCredentials(client_id, client_secret)
    auth_header = authorization_header(credentials.client_id, credentials.client_secret)
    credentials_flow = oauth.ClientCredentialsFlow(credentials)

    some_token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer'
    }

    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token,
        status=200
    )

    # WHEN: request_access_token is called
    token = credentials_flow._request_access_token()

    # THEN: The response should be the token string
    assert token == oauth.OAuthToken.from_json(some_token)
    token_request = responses.calls[0].request
    # the header variables contains the Authentication header
    assert token_request.headers['Authorization'] == auth_header['Authorization']
    # The payload should identify the grant_type
    assert token_request.body == 'grant_type=client_credentials'


@responses.activate
def test_oauth_client_credentials_request_token_should_raise_if_not_200(sptfy_environment):
    # GIVEN: ClientCredentialsFlow initialized with the client credentials
    client_id, client_secret, _ = sptfy_environment
    credentials = oauth.ClientCredentials(client_id, client_secret)
    credentials_flow = oauth.ClientCredentialsFlow(credentials)

    # and the endpoint does not answer correctly
    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json={'error': 'Something went wrong'},
        status=404
    )

    # WHEN: request_access_token is called
    # THEN: it should raise an exception
    with pytest.raises(oauth.SptfyOAuthError):
        credentials_flow._request_access_token()


@responses.activate
def test_oauth_client_credentials_successful_get_access_token(sptfy_environment):
    # GIVEN: ClientCredentialsFlow initialized with the client credentials
    credentials_flow = oauth.ClientCredentialsFlow()

    some_token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer'
    }

    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token,
        status=200
    )

    # WHEN: get_access_token is called
    token = credentials_flow.get_access_token()

    # THEN: It should return the token from either the API or memory
    assert token == oauth.OAuthToken.from_json(some_token)
    # The token should be saved in the manager memory,
    # so it's able to refresh when needed
    assert credentials_flow._current_token == token





@responses.activate
@patch('sptfy.oauth.time.time')
def test_oauth_client_credentials_get_access_token_with_expired(mock_time, sptfy_environment):
    # GIVEN: some expired OAuth token
    mock_time.side_effect = time_initial_values([0, 90])
    expired_token = oauth.OAuthToken(
        access_token='its-expired',
        scope='foo bar',
        expires_in=100,
        token_type='Bearer'
    )

    some_token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer'
    }

    responses.add(
        responses.POST,
        oauth.OAUTH_TOKEN_ENDPOINT,
        json=some_token,
        status=200
    )

    credentials_flow = oauth.ClientCredentialsFlow()
    credentials_flow._current_token = expired_token

    # WHEN: get_access_token is called
    token = credentials_flow.get_access_token()

    # THEN: the flow manager should replace the expired token
    assert credentials_flow._current_token == oauth.OAuthToken.from_json(some_token)
    # The returned token should be the new one instead of the expired
    assert token == oauth.OAuthToken.from_json(some_token)


@patch('sptfy.oauth.time.time')
def test_oauth_client_credentials_should_return_from_memory_if_not_expired(mock_time, sptfy_environment):
    # GIVEN: An OAuth token that has not expired
    mock_time.return_value = 0
    some_token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer'
    }

    credentials_flow = oauth.ClientCredentialsFlow()
    credentials_flow._current_token = oauth.OAuthToken.from_json(some_token)

    # WHEN: get_access_token is called with a non expired token
    token = credentials_flow.get_access_token()

    # THEN: the token returned should come from memory
    assert token == oauth.OAuthToken.from_json(some_token)
