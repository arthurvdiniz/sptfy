"""
    Module responsible for taking care of the OAuth authentication flow
    that is necessary to access the Spotify WEB API endpoints.

    It has classes for both the Client Credentials and Authorization Code
    flows.
"""
import os
import json
import time
import webbrowser
import base64

from enum import Enum
from urllib.parse import urlencode
from typing import Optional, List, Dict, Union
from requests import Session, HTTPError

import sptfy.utils as utils
from sptfy.types import JsonDict
from sptfy.errors import SptfyOAuthError, SptfyOAuthRedirect


OAUTH_TOKEN_ENDPOINT = 'https://accounts.spotify.com/api/token'
OAUTH_AUTHORIZATION_ENDPOINT = 'https://accounts.spotify.com/authorize'


def _is_subset(small_scope: List[str], big_scope: List[str]) -> bool:
    small_set, big_set = set(small_scope), set(big_scope)
    return small_set <= big_set


# Enum are frowned upon in python because they dont give any type safety
# guarantees. But I still decided to used them because they help with
# linters and tab completion in IDEs, the REPL and jupyter notebooks.
class Scope(Enum):
    """
        Implements the OAuth scopes that gives permission
        so clients from the Spotify Web API can access specific
        functionalities.
    """
    UGC_IMAGE_UPLOAD = 'ugc-image-upload'
    USER_FOLLOW_READ = 'user-follow-read'
    USER_FOLLOW_MODIFY = 'user-follow-modify'
    USER_READ_RECENTLY_PLAYED = 'user-read-recently-played'
    USER_TOP_READ = 'user-top-read'
    USER_READ_PLAYBACK_POSITION = 'user-read-playback-position'
    USER_LIBRARY_READ = 'user-library-read'
    USER_LIBRARY_MODIFY = 'user-library-modify'
    USER_READ_PLAYBACK_STATE = 'user-read-playback-state'
    USER_READ_CURRENTLY_PLAYING = 'user-read-currently-playing'
    USER_MODIFY_PLAYBACK_STATE = 'user-modify-playback-state'
    PLAYLIST_READ_COLLABORATIVE = 'playlist-read-collaborative'
    PLAYLIST_MODIFY_PRIVATE = 'playlist-modify-private'
    PLAYLIST_MODIFY_PUBLIC = 'playlist-read-private'
    STREAMING = 'streaming'
    APP_REMOTE_CONTROL = 'app-remote-control'
    USER_READ_EMAIL = 'user-read-email'
    USER_READ_PRIVATE = 'user-read-private'


class OAuthToken:
    """
    Represents the token return by an OAuth token endpoint.
    the access_token gives access to the protected resource

    static methods
    -------
    from_json(json: JsonDict): Instantiates the class from a json dictionary

    properties
    -------
    expires_at: time in seconds since epoch when this token will expire
    is_expired: checks if this token has expired
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
        """
        :param access_token: The OAuth access_token, used when accessing
            protected resources
        :param scope: The list of scopes assigned to this token
        :param expires_in: time in seconds until this token expires
        :param token_type: The OAuth token type (normally set to 'Bearer')
        :param refresh_token: Used in authorization code flow so the client
            can request new tokens without redirecting the user.
        """
        self.access_token = access_token
        self.scope = scope
        self.expires_in = expires_in
        self.token_type = token_type
        if refresh_token:
            self.refresh_token = refresh_token

        self._expires_at = int(time.time()) + self.expires_in

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OAuthToken):
            return False
        return (self.access_token == other.access_token and
                self.scope == other.scope and
                self.token_type == other.token_type)

    def __repr__(self):
        return ("OAuthToken(\n"
                f"   access_token={self.access_token},\n"
                f"   scope={self.scope},\n"
                f"   refresh_token={self.refresh_token},\n"
                f"   token_type={self.token_type},\n"
                f"   expires_in={self.expires_in}\n"
                ")")

    @property
    def scope(self) -> List[str]:
        return self._scope

    @scope.setter
    def scope(self, scopes: Union[List[str], List[Scope]]):
        if scopes and isinstance(scopes[0], Scope):
            self._scope = [scope.value for scope in scopes]
        else:
            self._scope = scopes

    @property
    def expires_at(self) -> int:
        """
        Gives the time when the token will expire as seconds since epoch
        """
        return self._expires_at

    @property
    def is_expired(self) -> bool:
        """
        Checks if this token has expired
        """
        now = int(time.time())
        return self.expires_at - now < 60

    @staticmethod
    def from_json(json: JsonDict):
        """
        Creates a new oauth token from a deserialized json

        :param json: Deserialized json (dict) representing the token
        """
        scopes = json['scope'].split()
        return OAuthToken(
            json['access_token'],
            scopes,
            json['expires_in'],
            json['token_type'],
            json.get('refresh_token')
        )

    def to_dict(self):
        """
        Creates a dictionary representation of the token
        """
        token = {
            'access_token': self.access_token,
            'scope': ' '.join(self.scope),
            'token_type': self.token_type,
            'expires_in': self.expires_in,
            'expires_at': self.expires_at,
        }
        if self.refresh_token:
            token['refresh_token'] = self.refresh_token
        return token

    
class ClientCredentials:
    """
    Represents the necessary credentials to authenticate into a OAuth protected
    endpoint

    static methods:
    -------
    from_env_variables(): instantiates the class from environment variables
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
    ) -> None:
        """
            client_id and client_secret are necessary for both authentication
            flows, so they are required. The redirect_uri is required for the
            authorization code flow, but not for client credentials.

            :param client_id: The Spotify OAuth client ID
            :param client_secret: The Spotify OAuth client secret
            :param redirect_uri: The client URI which the authentication server
                will redirect the user
            :param state: optional random string that helps avoiding
                attacks on the redirect_uri
            :param scope: The Spotify scopes needed for the wanted request
        """
        self.client_id = client_id
        self.client_secret = client_secret
        if redirect_uri:
            self.redirect_uri = redirect_uri
        if scope:
            self.scope = scope
        else:
            self._scope = []

        if state:
            self.state = state

    def __repr__(self):
        return ("ClientCredentials(\n"
                f"    client_id={self.client_id},\n"
                f"    client_secret={self.client_secret},\n"
                f"    redirect_uri={self.redirect_uri},\n"
                f"    scope={self.scope}\n"
                ")")

    @property
    def scope(self) -> List[str]:
        return self._scope

    @scope.setter
    def scope(self, scopes: Union[List[str], List[Scope]]):
        if scopes and isinstance(scopes[0], Scope):
            self._scope = [scope.value for scope in scopes]
        else:
            self._scope = scopes

    @staticmethod
    def from_env_variables(
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
            redirect_uri: Optional[str] = None
    ):
        """
        Instanties the client credentials from the environment variables.
        Gives flexibility so only part of the credentials be loaded from
        environment variables

        The redirect_uri is not obligatory, so if it's not set, it'll not
        throw an exception.

        :param client_id: if passed, will substitute the client id from env
        :param client_secret: if passed will substitute environment variable
        :param redirect_uri: if passed will substitute the redirect uri
            from env
        """
        try:
            client_id = client_id or os.environ['SPTFY_CLIENT_ID']
            client_secret = client_secret or os.environ['SPTFY_CLIENT_SECRET']
        except KeyError as err:
            raise SptfyOAuthError(
                f"Environment variable is not properly configured: {err}")

        # The redirect URI is not obligatory for the client_credentials flow
        # but should be specified if the client is intended to be used with
        # the authorization code flow
        redirect_uri = redirect_uri or os.getenv('SPTFY_REDIRECT_URI')

        return ClientCredentials(client_id, client_secret, redirect_uri)

    def _authorization_header(self) -> Dict[str, str]:
        """
        Generates the authentication header with base64 encoded client
        credentials as specified in the spotify documentation for
        authorization flows.
        """
        encoded = '{}:{}'.format(self.client_id, self.client_secret).encode('ascii')
        base64_code = base64.b64encode(encoded)

        return {'Authorization': f"Basic {base64_code.decode('ascii')}"}


class StubCache:
    """
        Implements the interface necessary for a token cache but does nothing.
        It's used by default.
    """
    def save_token(self, token: OAuthToken):
        pass

    def load_token(self) -> Optional[OAuthToken]:
        return None


class FileCache:
    """
        Implements a file based token cache, saving the token as json.
    """
    def __init__(self, file_path: str):
        """
        :param file_path: The path where the token should be persisted.
        """
        self.path = file_path

    def save_token(self, token: OAuthToken) -> None:
        with open(self.path, 'a') as cache:
            text = json.dumps(token.to_dict())
            cache.write(text)

    def load_token(self) -> Optional[OAuthToken]:
        try:
            with open(self.path) as cache:
                token = json.loads(cache.read())
                return OAuthToken.from_json(token)
        except FileNotFoundError:
            return None


class AuthStrategy:
    """
    Mixin which generates a random string for OAuth validation.
    Avoids Cross-Site Request Forgery attacks.
    Not used yet.
    """
    def get_state(self) -> str:
        state = secrets.token_urlsafe(32)
        self.current_state = state
        return state

    def check_state(self, state: str) -> bool:
        return self.current_state == state


class TerminalPromptAuth:
    """
        Implements an authentication flow that is appropriated for
        terminal based connections. It uses the webbrowser module
        from the standard library to open a browser window for
        user interaction.
    """
    def __init__(self, credentials: ClientCredentials, token_cache):
        self.credentials = credentials
        self.token_cache = token_cache

    def authorize(self):
        auth_url = self.build_url()
        try:
            webbrowser.open(auth_url)
        except webbrowser.Error:
            print(f'Please open the following url: {auth_url}')

        authorization_code = input('Please insert the code you were given: ')
        return self.retrieve_token(authorization_code)

    # Define a retrieve_token method here
    # It should get the token and save it to cache
    def retrieve_token(self, authorization_code: str):
        access_token = utils.retrieve_token(authorization_code, self.credentials)
        self.token_cache.save_token(access_token)
        return access_token


    def build_url(self) -> str:
        """
            Creates the authorization url with the right query
            string for the client.
        """
        query = {
            'client_id': self.credentials.client_id,
            'response_type': 'code',
            'redirect_uri': self.credentials.redirect_uri,
            'scope': ' '.join(self.credentials.scope)
        }

        params = urlencode(query)
        return f'{OAUTH_AUTHORIZATION_ENDPOINT}?{params}'


class WebBackendAuth:
    """
    Implements the authorizaiton flow for a web backend server.

    The methods are aimed to be used in views.
    """
    def __init__(self, credentials: ClientCredentials, token_cache):
        self.credentials = credentials
        self.token_cache = token_cache

    def authorize(self):
        raise SptfyOAuthRedirect(
            "No token available. User needs to authorize app.", 
            redirect_url=self.build_url()
        )

    def retrieve_token(self, authorization_code: str):
        token = utils.retrieve_token(authorization_code, self.credentials)
        self.token_cache.save_token(token)
        return token

    def build_url(self) -> str:
        """
            Creates the authorization url with the right query
            string for the client.
        """
        query = {
            'client_id': self.credentials.client_id,
            'response_type': 'code',
            'redirect_uri': self.credentials.redirect_uri,
            'scope': ' '.join(self.credentials.scope)
        }

        params = urlencode(query)
        return f'{OAUTH_AUTHORIZATION_ENDPOINT}?{params}'


class ClientCredentialsFlow:
    """
        Manages getting an access token using the Spotify API client
        credentials flow. This flow is used when the client is not
        representing an user and it wants to download data that is
        public available.

        This manager will take care of refreshing the token when needed.

        methods:
        -------
        get_access_token(): returns an [OAuthToken] for the client
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
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            **auth_header,
        }

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
            Gets the access token from memory or from the API, in case it's
            expired. This token cannot access endpoints for user data.

            :return: An OAuth token for the client
        """

        if self._current_token and not self._current_token.is_expired:
            return self._current_token

        token = self._request_access_token()
        self._current_token = token
        return token


class AuthorizationCodeFlow:
    """
        Manages getting an OAuth access token from the spotify WEB API using
        the authorization code flow. This flow is necessary to access user
        private data as it allows them to authenticate the application.

        This class will manage refreshing the token when necessary and saving
        it to cache, in case it's specified.

        methods:
        -------
        get_access_token() -> returns an OAuthToken for the user
    """
    def __init__(self, credentials, token_cache=None, auth_strategy=None):
        """
        The token cache is an object implementing two methods:
        save_token(OAuthToken) and load_token(), allowing to persist the token
        in memory in case it's necessary. In case no cache is given, the token
        is not persisted.

        The auth_strategy is an object implementing
        authorize(ClientCredentials) and on_authorization_response() that
        allows the client to redirect the user to the authentication endpoint
        in different ways (e.g. opening a web browser window or using HTTP
        redirection).

        In case the auth_strategy is not specified the authentication will
        be done by opening a browser window.

        The token cache API might change in the future.
        The auth strategy might change to be a single method instead.

        :param credentials: Instance of ClientCredentials with a specified
        redirect_uri
        :param token_cache: object implementing save_token and load_token
        :param auth_strategy: object implementing authorize and
        on_authorization_response
        """
        self.credentials = credentials
        self._session = Session()
        self._current_token = None

        if token_cache:
            self.token_cache = token_cache
        else:
            self.token_cache = StubCache()

        if auth_strategy:
            self.auth_strategy = auth_strategy
        else:
            self.auth_strategy = TerminalPromptAuth(self.credentials, self.token_cache)


    def get_access_token(self) -> OAuthToken:
        """
        Gets the access token while redirecting the user to authenticate
        the client application. The way of authentication is defined by
        the auth_strategy passed in the constructor.

        This method handles refreshing the token when it's expired.

        The token might be cached in case a token cache is given, but by
        default it's not. The token cache is an object that implements
        two methods: save_token(OAuthToken) and load_token().

        :raises SptfyOAuthError: when it's not able to retrieve an
        access_token, either by user interaction or by refresh_token
        """
        token = self._current_token

        # if token is not in memory, load from cache
        if not token:
            cached_token = self.token_cache.load_token()
            if self._validate_token(cached_token):
                token = cached_token

        # If token is not in cache or memory, the user
        # needs to authorize the application
        is_new_token = False
        if not token:
            is_new_token = True
            token = self.auth_strategy.authorize()

        if token.is_expired:
            is_new_token = True
            token = self._refresh_token(token)

        if is_new_token:
            self.token_cache.save_token(token)

        self._current_token = token
        return token

    def _refresh_token(self, old_token: OAuthToken) -> OAuthToken:
        """
            Gets a new access_token from the token endpoint using the
            refresh_token.

            :raises SptfyOAuthError: In case it's not able to refresh
            the current token.
        """
        auth_header = self.credentials._authorization_header()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            **auth_header
        }

        payload = {
            'refresh_token': old_token.refresh_token,
            'grant_type': 'refresh_token',
        }

        response = self._session.post(
            OAUTH_TOKEN_ENDPOINT,
            headers=headers,
            data=payload
        )

        if not response.ok:
            raise SptfyOAuthError(
                (f"Couldn't refresh token."
                 f"code: {response.status_code} reason: {response.reason}"))

        json_response = response.json()
        json_response['refresh_token'] = old_token.refresh_token
        return OAuthToken.from_json(json_response)

    # TODO: This method will be handled by the auth_strategy
    def _request_access_token(self) -> OAuthToken:
        """
            Gets an access_token from the authorize endpoint which requires
            user interaction. The way the interaction is handled is defined by
            the auth_strategy.

            :raises SptfyOAuthError: when it's not able to retrieve an
            access_token
        """
        # Authorization strategy is user defined
        # (could be terminal prompt, http server)
        self.auth_strategy.authorize(self.credentials)
        code = self.auth_strategy.on_authorization_response()

        auth_header = self.credentials._authorization_header()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            **auth_header,
        }

        payload = {
            'redirect_uri': self.credentials.redirect_uri,
            'scope': ' '.join(self.credentials.scope),
            'code': code,
            'grant_type': 'authorization_code'
        }

        response = self._session.post(
            OAUTH_TOKEN_ENDPOINT,
            data=payload,
            headers=headers,
        )

        if response.status_code != 200:
            error_response = response.json()
            raise SptfyOAuthError(
                (f"error: {error_response['error']}"
                 f"description: {error_response['error_description']}"),
                error=error_response['error'],
                error_description=error_response['error_description']
            )

        return OAuthToken.from_json(response.json())

    def _validate_token(self, token: Optional[OAuthToken]) -> bool:
        """
            Validates if a saved token has the correct scopes so it
            cant be tampered with.
        """
        if token is None:
            return False

        return _is_subset(self.credentials.scope, token.scope)
