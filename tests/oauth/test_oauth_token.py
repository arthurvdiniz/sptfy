import base64
import pytest
import responses
from unittest.mock import patch

import sptfy.oauth as oauth


def authorization_header(client_id, client_secret):
    credentials_header = f'{client_id}:{client_secret}'.encode(encoding='ascii')
    authorization_header = base64.b64encode(credentials_header)
    return {'Authorization': f"Basic {authorization_header.decode('ascii')}"}


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
    assert oauth_token.refresh_token is None


@patch('sptfy.oauth.time.time')
def test_oauth_token_expires_at(mock_time):
    # GIVEN: an expiration timespan from the token
    token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 3600,
        'token_type': 'Bearer',
    }

    mock_time.return_value = 10
    oauth_token = oauth.OAuthToken.from_json(token)

    # WHEN: expires_at is called
    # THEN: The expiration timestamp should be returned
    assert oauth_token.expires_at == mock_time.return_value + token['expires_in']
    oauth_token.expires_at
    # the expiration timestamp should not be recalculated
    assert mock_time.call_count == 1


@patch('sptfy.oauth.time.time')
def test_oauth_token_is_expired(mock_time):
    # GIVEN: An expired token
    mock_time.side_effect = [0, 30, 101]

    json_token = {
        'access_token':  'random-string-from-server',
        'scope': 'foo bar',
        'expires_in': 100,
        'token_type': 'Bearer',
    }

    token = oauth.OAuthToken.from_json(json_token)

    # THEN: token should not be expired after 30 milliseconds (i think, maybe seconds)
    assert not token.is_expired
    # token should be expired after 100 milliseconds
    assert token.is_expired
