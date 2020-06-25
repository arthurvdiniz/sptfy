import base64
import pytest

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
    with pytest.raises(oauth.SptfyOAuthError) as err:
        oauth.ClientCredentials.from_env_variables()

    assert "SPTFY_CLIENT_ID" in str(err) or "SPTFY_CLIENT_SECRET" in str(err)


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


def test_credentials_should_read_scopes_enum(sptfy_environment):
    # GIVEN: The credentials from program variables
    client_id, client_secret, _ = sptfy_environment
    # and the spotify scope as enums
    scopes = [oauth.Scope.USER_LIBRARY_MODIFY, oauth.Scope.USER_LIBRARY_READ]

    # WHEN: the scope is set
    credentials = oauth.ClientCredentials(client_id, client_secret, scope=scopes)

    # THEN: The scopes are defined as raw strings (instead of enums)
    assert credentials.scope == [scope.value for scope in scopes]


def test_credentials_scope_should_work_with_raw_strings(sptfy_environment):
    # GIVEN: the credentials from program variables
    client_id, client_secret, _ = sptfy_environment
    # and the spotify scope as raw strings
    scopes = ['user-library-modify', 'user-library-read']

    # WHEN: the scope is given
    credentials = oauth.ClientCredentials(client_id, client_secret, scope=scopes)

    # THEN: The scope should be set as is
    assert credentials.scope == scopes


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
