from urllib.parse import urlencode, quote 

import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify


@responses.activate
def test_spotify_tracks_get_should_call_endpoint(
    sptfy_environment, 
    file_cache_with_token
):
    # Given: An user specified track id
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/tracks/{track_id}',
        json={'track': {'name': 'Labyrinth', 'artist': 'Surf Disco'}},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # When: trying to retrieve a track
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.get(track_id=track_id)

    assert response['track'] == {'name': 'Labyrinth', 'artist': 'Surf Disco'} 


@responses.activate
def test_spotify_tracks_get_should_accept_transform(
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
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # Given: a transformer that retrieves the track's name
    def retrieve_name(response):
        return response['track']['name']

    # When: trying to retrieve a track with a specific transformer
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.get(track_id=track_id, transformer=retrieve_name)

    # Then: the result should be the given by the transformer 
    # instead of the json
    assert response == 'Labyrinth'


@responses.activate
def test_spotify_tracks_get_should_accept_cached_transform(
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
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # Given: a transformer that retrieves the track's name, 
    # that its cached on the Spotify object.
    sptfy = Spotify(oauth_manager=oauth_manager)
    
    @sptfy.transformer('tracks.get')
    def retrieve_name(response):
        return response['track']['name']

    # When: trying to retrieve a track with a specific transformer
    response = sptfy.tracks.get(track_id=track_id)

    assert response == 'Labyrinth'


@responses.activate
def test_tracks_search_should_hit_correct_endpoint(
    sptfy_environment,
    file_cache_with_token
):
    # Given: An inexistent track object (i.e. 404)
    track_name = 'The Lost Chord'
    search_query = {
        'q': quote(track_name), 
        'type': 'track',
    }
    params = urlencode(search_query)

    json_response = {
        'tracks': {
            'items': ['track-object-1', 'track-object-2', 'track-object-3']
        }
    }
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/search?{params}',
        json=json_response,
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    sptfy = Spotify(oauth_manager=oauth_manager)

    # When: searching for a track
    response = sptfy.tracks.search(track_name)

    # Then: it should receive a list of track objects 
    # that matches the query
    assert len(response['tracks']['items']) == 3


@responses.activate
def test_tracks_audio_features_should_call_correct_endpoint(
    sptfy_environment, 
    file_cache_with_token
):
    # Given: An user specified track id
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/audio-features/{track_id}',
        json={'id': track_id, 'acousticness': 0.78, 'duration_ms': 12000},
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # When: trying to retrieve a track
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.audio_features(track_id=track_id)

    # TODO: change these assertions to query matchers from responses
    assert response['id'] == track_id 
    assert response['acousticness'] == 0.78


@responses.activate
def test_tracks_audio_analysis_should_call_correct_endpoint(
    sptfy_environment, 
    file_cache_with_token
):
    analysis = {'bars': [{'start': 120.1, 'duration': 0.3, 'confidence': 0.60}]}
    # Given: An user specified track id
    track_id = 'some-track-id'
    responses.add(
        responses.GET,
        f'https://api.spotify.com/v1/audio-analysis/{track_id}',
        json=analysis,
        status=200,
    )

    credentials = oauth.ClientCredentials.from_env_variables()
    oauth_manager = oauth.AuthorizationCodeFlow(
        credentials, 
        token_cache=file_cache_with_token
    )

    # When: trying to retrieve a track
    sptfy = Spotify(oauth_manager=oauth_manager)
    response = sptfy.tracks.audio_analysis(track_id=track_id)

    # TODO: change this assertion to query matchers from responses
    assert response == analysis


