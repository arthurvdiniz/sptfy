import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify


@responses.activate
def test_spotify_disable_transformers_should_reset_transformers_temporarily(
    sptfy_environment, 
    file_cache_with_token
):
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(credentials, token_cache=file_cache_with_token)

    sptfy = Spotify(oauth_manager=oauth_manager)

    # Given: a transformer that retrieves the track's name
    @sptfy.transformer('tracks.get')
    def retrieve_name(response):
        return response['track']['name']

    sess = sptfy.session()
    # When: trying to retrieve a track with a specific transformer
    response = sess.tracks.get(track_id=track_id, transformer=retrieve_name)

    # Then: the result should be the given by the transformer 
    # instead of the json
    assert response == 'Labyrinth'

    # When: the disable_transformers context manager is used
    with sess.disable_transformers():
        response = sess.tracks.get(track_id)

    # Then: the response should not be transformed
    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Disco'}

    # Makes sure the context manager resets the transformers to
    # the way it was before

    # When: retrieving data after the context manager finished
    response = sess.tracks.get(track_id)

    # Then: the result should be transformed again
    assert response == 'Labyrinth'
