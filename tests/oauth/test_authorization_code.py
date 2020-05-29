import json
import pytest

import sptfy.oauth as oauth


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
    open(cache_file, 'a').close()   # Creates an empty file
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
    open(cache_path, 'a').close()   # Creates an empty file
    token_str = json.dumps(token)
    with cache_path.open('w') as cache_file:
        cache_file.write(token_str)

    cache = oauth.FileCache(cache_path)

    # WHEN: FileCache.load_token is called
    loaded_token = cache.load_token()

    # THEN: the token should be loaded to memory
    assert loaded_token == oauth.OAuthToken.from_json(token)
