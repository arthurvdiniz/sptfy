import base64
import json
import pytest
import requests
import responses
from unittest.mock import patch

import sptfy.oauth as oauth


CRED_INIT_VARS = [
        (
            {'client_id': 'client-id-123456', 'client_secret': 'secret-key-456789'},
            {'scope': [], 'state':None, 'redirect_uri': None}
        ),
        (
            {'client_id': 'client-id-123456', 'client_secret':'secret-key-456789', 'redirect_uri': 'http://localhost:4200/'},
            {'scope': [], 'state': None}
        ),
        (
            {'client_id': 'client-id-123456', 'client_secret': 'secret-key-456789', 'redirect_uri': 'http://localhost:4200/', 'state': 'random-state-string'},
            {'scope': []}
        ),
        (
            {'client_id': 'client-id-123456', 'client_secret': 'secret-key-456789', 'redirect_uri': 'http://localhost:4200/', 'state': 'random-state-string', 'scope': ['foo', 'bar']},
            {},
        )
]


@pytest.fixture()
def sptfy_environment(monkeypatch):
    client_id = 'test-client-id-123456'
    client_secret = 'test-secret-key-456789'
    redirect_uri = 'http://localhost:4200/'

    monkeypatch.setenv('SPTFY_CLIENT_ID', client_id)
    monkeypatch.setenv('SPTFY_CLIENT_SECRET', client_secret)
    monkeypatch.setenv('SPTFY_REDIRECT_URI', redirect_uri)

    return client_id, client_secret, redirect_uri


def authorization_header(client_id, client_secret):
    credentials_header = f'{client_id}:{client_secret}'.encode(encoding='ascii')
    authorization_header = base64.b64encode(credentials_header)
    return {'Authorization': f"Basic {authorization_header.decode('ascii')}"}


def test_load_credentials_from_env(sptfy_environment):
    # GIVEN: The necessary environment variables
    client_id, client_secret, redirect_uri = sptfy_environment

    # WHEN: ClientCredentials is created from env variables
    credentials = oauth.ClientCredentials.from_env_variables()

    # THEN: We should be able to access the client identification
    assert credentials.client_id == client_id
    assert credentials.client_secret == client_secret
    assert credentials.redirect_uri == redirect_uri


def test_load_credentials_without_env_should_throw():
    # GIVEN: No environment variables
    # WHEN: Initialized with from_env_variables()
    # THEN: It should raise an exception
    with pytest.raises(KeyError):
        oauth.ClientCredentials.from_env_variables()


@pytest.mark.parametrize("test_input,defaults", CRED_INIT_VARS)
def test_credentials_initialization(test_input, defaults):

    # WHEN: Initialized with custom variables 
    credentials = oauth.ClientCredentials(**test_input)

    # THEN: Credentials should be initialized with default values
    for key, value in defaults.items():
        assert getattr(credentials, key) == value


def test_credentials_initialization_has_default_variables(sptfy_environment):
    # GIVEN: The credentials stored in program variables
    client_id, client_secret, redirect_uri = sptfy_environment

    # WHEN: Initialized only with client ID and client secret
    credentials = oauth.ClientCredentials(client_id, client_secret)

    # THEN: It should have an empty scope and no state
    assert credentials.redirect_uri is None
    assert credentials.scope == []
    assert credentials.state is None


def test_credentials_get_auth_header(sptfy_environment):
    # GIVEN: A client id and a client_secret
    client_id, client_secret, _ = sptfy_environment
    credentials = oauth.ClientCredentials(client_id, client_secret)
    auth_header = authorization_header(credentials.client_id, credentials.client_secret)
    
    # WHEN: authentication_header is called
    header = credentials._authorization_header()

    # THEN: The header should be a dict containing a base64 encoded
    # string that represents the client_id and client_secret
    assert header['Authorization'] == auth_header['Authorization']


def test_oauth_token_from_json():
    # GIVEN: A dict with the token information
    token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer',
    }

    # WHEN: loading an OAuthToken from a json dict
    oauth_token = oauth.OAuthToken.from_json(token)

    # THEN: the scope parsed into a list
    assert oauth_token.scope == ['foo', 'bar']
    # Refresh token is optional (client credentials flow doesnt use it)
    assert oauth_token.refresh_token == None


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
        'client_id': client_id,
        'scope': 'foo bar',
        'expires_in': 3600,
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
    assert token == some_token
    token_request = responses.calls[0].request
    # the header variables contains the Authentication header
    assert token_request.headers['Authorization'] == auth_header['Authorization']
    # The payload should indentify the grant_type
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
