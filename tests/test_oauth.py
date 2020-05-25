import pytest
import sptfy.oauth as oauth

@pytest.fixture()
def sptfy_environment(monkeypatch):
    client_id = 'test-client-id-123456'
    client_secret = 'test-secret-key-456789'
    redirect_uri = 'http://localhost:4200/'

    monkeypatch.setenv('SPTFY_CLIENT_ID', client_id)
    monkeypatch.setenv('SPTFY_CLIENT_SECRET', client_secret)
    monkeypatch.setenv('SPTFY_REDIRECT_URI', redirect_uri)

    return client_id, client_secret, redirect_uri


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


def test_credentials_initialization_has_default_variables(sptfy_environment):
    # GIVEN: The credentials stored in program variables
    client_id, client_secret, redirect_uri = sptfy_environment

    credentials = oauth.ClientCredentials(client_id, client_secret, redirect_uri)

    # THEN: It should have an empty scope and no state
    assert credentials.scope == []
    assert credentials.state == None
