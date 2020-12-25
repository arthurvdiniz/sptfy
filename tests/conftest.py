import pytest


@pytest.fixture()
def sptfy_environment(monkeypatch):
    client_id = 'test-client-id-123456'
    client_secret = 'test-secret-key-456789'
    redirect_uri = 'http://localhost:4200/'

    monkeypatch.setenv('SPTFY_CLIENT_ID', client_id)
    monkeypatch.setenv('SPTFY_CLIENT_SECRET', client_secret)
    monkeypatch.setenv('SPTFY_REDIRECT_URI', redirect_uri)

    return client_id, client_secret, redirect_uri


@pytest.fixture
def empty_environment(monkeypatch):
    monkeypatch.delenv('SPTFY_CLIENT_ID', raising=False)
    monkeypatch.delenv('SPTFY_CLIENT_SECRET', raising=False)
    monkeypatch.delenv('SPTFY_REDIRECT_URI', raising=False)
