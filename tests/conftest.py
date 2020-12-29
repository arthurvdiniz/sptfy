import os
import sys
import time

import pytest

import sptfy.oauth as oauth

sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))


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
        created_at=int(time.time()),
        scope=['foo', 'bar']
    )

    token_file_cache.save_token(token)
    return token_file_cache


