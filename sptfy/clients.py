import functools
from typing import (
    Optional, Any, Callable, Union,
)
from contextlib import contextmanager

import sptfy.oauth as oauth
import sptfy.utils as utils
from sptfy.endpoints import (
    TracksEndpoint, PlaylistEndpoint, 
    ArtistsEndpoint, AlbumsEndpoint
)


class _SpotifyClient:
    def __init__(self):
        self.transformer_cache = {}

    def transformer(self, endpoint: str):
        """
        Registers a transformer to this Spotify client.

        Works similarly to Flask's @app.route() decorator.
        """
        def add_transform_to_cache(func):
            self.transformer_cache[endpoint] = func
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper
        return add_transform_to_cache


class SpotifySession:
    def __init__(self, oauth_manager, transformer_cache, context=None):
        self.oauth_manager = oauth_manager
        self.transformer_cache = dict(transformer_cache) # Shallow copy
        self.context = context

        self.tracks = TracksEndpoint(self.oauth_manager, self.transformer_cache)
        self.playlists = PlaylistEndpoint(self.oauth_manager, self.transformer_cache)
        self.artists = ArtistsEndpoint(self.oauth_manager, self.transformer_cache)
        self.albums = AlbumsEndpoint(self.oauth_manager, self.transformer_cache)

    @contextmanager
    def disable_transformers(self):
        """
        A context manager that temporarily disables this 
        Spotify client's transformers in case the user needs 
        to retrieve more data than it's given by the transformer.

        Usage
        -------
        with sess.disable_transformers():
            sess.tracks.get('some-id')
        """
        try:
            cached_transformers = dict(self.transformer_cache)
            self.transformer_cache.clear() 
            yield
        finally:
            self.transformer_cache.update(cached_transformers)


class AsyncSpotifySession:
    tracks: TracksEndpoint
    playlists: PlaylistEndpoint
    artists: ArtistsEndpoint
    albums: AlbumsEndpoint

    def __init__(self, oauth_manager, transformer_cache, context=None):
        self.oauth_manager = oauth_manager
        self.transformer_cache = dict(transformer_cache) # Shallow copy
        self.context = context

        self.tracks = AsyncEndpoint(
            TracksEndpoint(self.oauth_manager, self.transformer_cache)
        )
        self.playlists = AsyncEndpoint(
            PlaylistEndpoint(self.oauth_manager, self.transformer_cache)
        )
        self.artists = AsyncEndpoint(
            ArtistsEndpoint(self.oauth_manager, self.transformer_cache)
        )
        self.albums = AsyncEndpoint(
            AlbumsEndpoint(self.oauth_manager, self.transformer_cache)
        )

    @contextmanager
    def disable_transformers(self):
        """
        A context manager that temporarily disables this 
        Spotify client's transformers in case the user needs 
        to retrieve more data than it's given by the transformer.

        Usage
        -------
        with sess.disable_transformers():
            sess.tracks.get('some-id')
        """
        try:
            cached_transformers = dict(self.transformer_cache)
            self.transformer_cache.clear() 
            yield
        finally:
            self.transformer_cache.update(cached_transformers)


class Spotify(_SpotifyClient):
    """
    Represents an user session to the Spotify Web API.

    By default it uses the Authorization Code Flow, but it can 
    be changed by using the [oauth_manager] argument.
    """
    BASE_URL = 'https://api.spotify.com/v1'

    def __init__(
        self, 
        oauth_manager: Optional[oauth.OAuthManager] = None
    ):
        super().__init__()

        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

    def session(self, context=None) -> SpotifySession:
        return SpotifySession(
            self.oauth_manager, 
            self.transformer_cache,
            context
        )


class AsyncSpotify(_SpotifyClient):
    def __init__(
        self, 
        oauth_manager: Optional[oauth.OAuthManager] = None
    ):
        super().__init__()

        if oauth_manager:
            self.oauth_manager = oauth_manager
        else:
            credentials = oauth.ClientCredentials.from_env_variables()
            self.oauth_manager = oauth.AuthorizationCodeFlow(credentials)

        self.oauth_manager = oauth.LockOAuthManager(self.oauth_manager)

    def session(self, context=None) -> AsyncSpotifySession:
        return AsyncSpotifySession(
            self.oauth_manager,
            self.transformer_cache,
            context
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

    def __getattr__(self, name: str) -> Union[Any, Callable]:
        attr = getattr(self.endpoint, name)

        if not callable(attr):
            return attr

        async def _wrapper(*args, **kwargs):
            return await utils.run_async(attr, *args, **kwargs)

        return _wrapper

