import os
from typing import Optional, List


class ClientCredentials:
    """
    Represents the necessary credentials to authenticate into a OAuth protected endpoint
    """
    client_id: str
    client_secret: str
    redirect_uri: str
    state: Optional[str] = None
    scope: List[str] = []

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    @staticmethod
    def from_env_variables():
        client_id = os.environ['SPTFY_CLIENT_ID']
        client_secret = os.environ['SPTFY_CLIENT_SECRET']
        redirect_uri = os.environ['SPTFY_REDIRECT_URI']

        return ClientCredentials(client_id, client_secret, redirect_uri)
