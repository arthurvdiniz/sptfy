"""
    Module responsible for taking care of the OAuth authentication flow
    that is necessary to access the Spotify WEB API endpoints.

    It has classes for both the Client Credentials and Authorization Code
    flows.
"""
import os
import time
import base64
from typing import Optional, List, Dict, NamedTuple, Any
from requests import Session

from sptfy.types import JsonDict


OAUTH_TOKEN_ENDPOINT = 'https://accounts.spotify.com/api/token'


class SptfyOAuthError(Exception):
    pass


class OAuthToken:
    """
        Represents the token return by an OAuth token endpoint.
        the access_token gives access to the protected resource
    """
    access_token: str
    scope: List[str]
    expires_in: int
    token_type: str
    refresh_token: Optional[str] = None
    _expires_at: int

    def __init__(
            self,
            access_token: str,
            scope: List[str],
            expires_in: int,
            token_type: str,
            refresh_token: Optional[str] = None
        ):
        self.access_token = access_token
        self.scope = scope
        self.expires_in = expires_in
        self.token_type = token_type
        if refresh_token:
            self.refresh_token = refresh_token

        self._expires_at = int(time.time()) + self.expires_in

    @property
    def expires_at(self) -> int:
        return self._expires_at

    @property
    def is_expired(self) -> bool:
        now = int(time.time())
        return self.expires_at - now < 60

    @staticmethod
    def from_json(json: JsonDict):
        scopes = json['scope'].split()
        return OAuthToken(
            json['access_token'],
            scopes,
            json['expires_in'],
            json['token_type'],
            json.get('refresh_token')
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OAuthToken):
            return False
        return self.access_token == other.access_token and self.scope == other.scope and self.token_type == other.token_type


class ClientCredentials:
    """
    Represents the necessary credentials to authenticate into a OAuth protected endpoint
    """
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None
    state: Optional[str] = None
    scope: List[str] = []

    def __init__(
            self,
            client_id: str,
            client_secret: str,
            redirect_uri: str = None,
            state: str = None,
            scope: List[str] = None,
        ):
        """
            client_id and client_secret are necessary for both authentication flows, so they are required.
            The redirect_uri is required for the authorization code flow, but not for client credentials.

            :param client_id: The Spotify OAuth client ID
            :param client_secret: The Spotify OAuth client secret
            :param redirect_uri: The client URI which the authentication server will redirect the user
            :param state: optional random string that helps with avoiding attacks on the redirect_uri
            :param scope: The Spotify scopes needed for the wanted request
        """
        self.client_id = client_id
        self.client_secret = client_secret
        if redirect_uri:
            self.redirect_uri = redirect_uri
        if scope:
            self.scope = scope
        if state:
            self.state = state

    @staticmethod
    def from_env_variables(
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            redirect_uri: Optional[str] = None
        ):
        try:
            client_id = client_id or os.environ['SPTFY_CLIENT_ID']
            client_secret = client_secret or os.environ['SPTFY_CLIENT_SECRET']
        except KeyError as e:
            raise SptfyOAuthError(f"Environment variable is not properly configured: {e}")

        # The redirect URI is not obligatory for the client_credentials flow
        # but should be specified if the client is intended to be used with
        # the authorization code flow
        redirect_uri = redirect_uri or os.getenv('SPTFY_REDIRECT_URI')

        return ClientCredentials(client_id, client_secret, redirect_uri)

    def _authorization_header(self) -> Dict[str, str]:
        """
        Generates the authentication header with base64 encoded client credentials
        as specified in the spotify documentation for authorization flows.
        """
        encoded = '{}:{}'.format(self.client_id, self.client_secret).encode('ascii')
        base64_code = base64.b64encode(encoded)
 
        return {'Authorization': f"Basic {base64_code.decode('ascii')}"}



class ClientCredentialsFlow:
    """
        Manages getting an access token using the Spotify API client credentials flow.
        This flow is used when the client is not representing an user and it wants to
        download data that is public available.

        This manager will take care of refreshing the token when needed.
    """
    credentials: ClientCredentials
    _session: Session
    _current_token: Optional[OAuthToken] = None

    def __init__(
            self,
            credentials: Optional[ClientCredentials] = None,
            session: Optional[Session] = None
        ):

        if credentials:
            self.credentials = credentials
        else:
            self.credentials = ClientCredentials.from_env_variables()

        if session:
            self._session = session
        else:
            self._session = Session()

    def _request_access_token(self) -> OAuthToken:
        """
            Gets the access token from the token endpoint directly.
        """
        payload = {'grant_type': 'client_credentials'}
        auth_header = self.credentials._authorization_header()
        headers = {'Content-Type': 'application/x-www-form-urlencoded', **auth_header}

        response = self._session.post(
            OAUTH_TOKEN_ENDPOINT,
            headers=headers,
            data=payload,
        )

        if response.status_code != 200:
            raise SptfyOAuthError(response.reason)

        return OAuthToken.from_json(response.json())

    def get_access_token(self) -> OAuthToken:
        """
            Gets the access token from memory or from the API, in case it's expired.
            This token cannot access endpoints for user data.

            :return: An OAuth token for the client
        """

        if self._current_token and not self._current_token.is_expired:
            return self._current_token

        token = self._request_access_token()
        self._current_token = token
        return token
