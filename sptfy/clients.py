import functools
import typing as t
from contextlib import contextmanager

import sptfy.oauth as oauth
import sptfy.utils as utils
from sptfy.endpoints import TracksEndpoint, PlaylistEndpoint


class Spotify:
    """
    Represents an user session to the Spotify Web API.

    By default it uses the Authorization Code Flow, but it can 
    be changed by using the [oauth_manager] argument.
    """
    BASE_URL = 'https://api.spotify.com/v1'

    def __init__(self, oauth_manager=None):
        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

        self.transformer_cache = {}

        self.tracks = TracksEndpoint(self.oauth_manager, self.transformer_cache)
        self.playlists = PlaylistEndpoint(self.oauth_manager, self.transformer_cache)

    def transformer(self, endpoint: str):
        """
        Registers a transformer to this Spotify session.

        Works similarly to Flask's @app.route() decorator.
        """
        def add_transform_to_cache(func):
            self.transformer_cache[endpoint] = func
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return add_transform_to_cache

    @contextmanager
    def disable_transformers(self):
        """
        A context manager that temporarily disables this 
        Spotify client's transformers in case the user needs 
        to retrieve more data than it's given by the transformer.

        Usage
        -------
        with sptfy.disable_transformers():
            sptfy.tracks.get('some-id')
        """
        try:
            cached_transformers = dict(self.transformer_cache)
            self.transformer_cache.clear() 
            yield
        finally:
            self.transformer_cache.update(cached_transformers)


class AsyncSpotify:
    tracks: TracksEndpoint
    playlists: PlaylistEndpoint

    def __init__(self, oauth_manager=None):
        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

        self.transformer_cache = {}

        self.playlists = AsyncEndpoint(
            PlaylistEndpoint(self.oauth_manager, self.transformer_cache)
        )
        self.tracks = AsyncEndpoint(
            TracksEndpoint(self.oauth_manager, self.transformer_cache)
        )


class AsyncEndpoint:
    """
    Transforms an endpoint into an async one.

    The asynchronous tasks are executed by offloading a synchronous task into
    a executor thread. Due to the GIL, this method is only useful with IO
    bound tasks.
    """
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def __getattr__(self, name: str) -> t.Union[t.Any, t.Callable]:
        attr = getattr(self.endpoint, name)

        if not callable(attr):
            return attr

        async def _wrapper(*args, **kwargs):
            return await utils.run_async(attr, *args, **kwargs)

        return _wrapper

