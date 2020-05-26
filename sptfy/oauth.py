"""
    Module responsible for taking care of the OAuth authentication flow
    that are necessary to access the Spotify WEB API endpoints.
"""
import os
import base64
from typing import Optional, List, Dict
from requests import Session


OAUTH_TOKEN_ENDPOINT = 'https://accounts.spotify.com/api/token'


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
        client_id = client_id or os.environ['SPTFY_CLIENT_ID']
        client_secret = client_secret or os.environ['SPTFY_CLIENT_SECRET']
        redirect_uri = redirect_uri or os.getenv('SPTFY_REDIRECT_URI')

        return ClientCredentials(client_id, client_secret, redirect_uri)

    def _authentication_header(self) -> Dict[str, str]:
        encoded = f'{self.client_id}:{self.client_secret}'.encode('ascii')
        base64_code = base64.b64encode(encoded)
        
        return {'Authentication': f"Basic {base64_code.decode('ascii')}"}



class ClientCredentialsFlow:
    """
        Manages getting an access token using the Spotify API client credentials flow.
        This flow is used when the client is not representing an user
    """
    credentials: ClientCredentials
    _session: Session

    def __init__(self, credentials: Optional[ClientCredentials] = None, session: Optional[Session] = None):

        if credentials:
            self.credentials = credentials
        else:
            self.credentials = ClientCredentials.from_env_variables()

        if session:
            self._session = session
        else:
            self._session = Session()

    def _request_access_token(self):
        payload = {'grant_type': 'client_credentials'}
        auth_header = self.credentials._authentication_header()

        response = self._session.post(
            OAUTH_TOKEN_ENDPOINT,
            headers=auth_header,
            data=payload,
        )

        return response.json() 
