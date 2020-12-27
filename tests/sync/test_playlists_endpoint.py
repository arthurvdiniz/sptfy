from urllib.parse import urlencode

import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify


@responses.activate
def test_playlists_add_to_should_hit_correct_endpoint(
    sptfy_environment,
    file_cache_with_token
):
    playlist_id = 'some-playlist-id'
    tracks = ['some-track-id', 'another-track-id', 'several-track-ids']
    responses.add(
        responses.POST,
        f'https://api.spotify.com/v1/playlists/{playlist_id}/tracks',
        json={'status': 'ok'},
        status=200,
        match=[
            responses.json_params_matcher({ 'uris': tracks })
        ]
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    sptfy = Spotify(oauth_manager=manager)
    sess = sptfy.session()

    # When: trying to add songs to a playlist
    sess.playlists.add_to(playlist_id, songs=tracks)

    # Then: it should hit the correct endpoint


@responses.activate
@pytest.mark.parametrize('songs', [
    None, 
    ['some-song-id', 'other-song-id', 'more-song-id']
])
def test_playlists_create_should_hit_correct_endpoint(
    songs,
    sptfy_environment,
    file_cache_with_token
):
    playlist_name = 'My awesome playlist'
    playlist_id = 'some-playlist-id'
    user_id = 'my-spotify-user-id'

    responses.add(
        responses.GET,
        f"https://api.spotify.com/v1/me",
        json={ 'id': user_id },
        status=200
    )

    responses.add(
        responses.POST,
        f"https://api.spotify.com/v1/users/{user_id}/playlists",
        json={'id': playlist_id},
        status=200,
    )

    post_body = None
    if songs:
        post_body = {'uris': songs}

    responses.add(
        responses.POST,
        f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks",
        json={'status': 'ok'},
        status=200,
        match=[
            responses.json_params_matcher(post_body)
        ]
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    sptfy = Spotify(oauth_manager=manager)
    sess = sptfy.session()

    # When: trying to create a playlist
    sess.playlists.create(playlist_name, songs=songs)

    # Then: it should hit the correct endpoint without errors

