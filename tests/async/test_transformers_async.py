import re
import asyncio
import typing as t

import pytest
import responses

from test_utils import search_params

import sptfy.oauth as oauth
from sptfy.clients import AsyncSpotify
from sptfy.types import JsonDict


@pytest.mark.skip(reason="Still don't know how to properly solve this problem")
@pytest.mark.asyncio
async def test_disable_transformers_should_apply_only_to_its_context(
    sptfy_environment,
    file_cache_with_token
):
    with responses.RequestsMock() as rsps:
        artists_params = search_params('Gorillaz', 'artist')
        tracks_params = search_params('Feel Good Inc', 'track')

        artists_obj = {
            'artists': {
                'items': [
                    { 'name': 'Gorillaz'},
                    { 'name': 'More Gorillaz'},
                    { 'name': 'Not Gorillaz'},
                ]
            }
        }

        rsps.add(
            responses.GET,
            f'https://api.spotify.com/v1/search?{artists_params}',
            json=artists_obj,
            status=200
        )

        rsps.add(
            responses.GET,
            f'https://api.spotify.com/v1/search?{tracks_params}',
            json=artists_obj,
            status=200
        )

        credentials = oauth.ClientCredentials.from_env_variables()
        manager = oauth.AuthorizationCodeFlow(
            credentials, 
            token_cache=file_cache_with_token
        )

        # Given: an spotify client configured with
        # a transfomer
        sptfy = AsyncSpotify(oauth_manager=manager)

        @sptfy.transformer('artists.search')
        def retrieve_track_names(response: JsonDict) -> t.List[str]:
            return [track['name'] for track in response['artists']['items']]

        sess = sptfy.session()

        async def tracks_no_transformers():
            with sess.disable_transformers():
                await asyncio.sleep(0.1)
                return await sess.tracks.search('Feel Good Inc')

        async def artists_with_transformers():
            response = await sess.artists.search('Gorillaz')
            print("artists response:")
            print(response)
            return response

        response = await asyncio.gather(tracks_no_transformers(), artists_with_transformers())

        assert isinstance(response[0], dict)
        assert isinstance(response[1], list)

