
# Sptfy: An ergonomic and easy to remember Spotify Web API client

**This library is currently a work in progress. Some APIs are not well defined yet and some part of the design is not completely finished**

## Usage

The API follows the idea that the methods should follow an easy to remember pattern so the user doesn't have to keep pulling up documentation in order to discover how to achieve what it wants. Also the API tries to map to how the endpoints are organized in the Spotify Web API so that it's simple to find documentation about the API usage, but this rule is broken is some places.

```Python
from sptfy.sync import Spotify

# Starts a session
sptfy = Spotify()

# Retrieves an Spotify track (i.e. song)
track = sptfy.tracks.get('track-id')
playlist = sptfy.playlists.get('playlist-id')
album = sptfy.albums.get('album-id')
artist = sptfy.artists.get('artist-id')

# Searching
track = sptfy.tracks.search('Feel Good Inc.')
playlist = sptfy.playlists.search('Best of 2019')
album = sptfy.albums.search('To Pimp a Butterfly')
artist = sptfy.artists.search('Snarky Puppy')

# Playlist manipulation
sptfy.playlists.create('My Awesome Playlist', songs=['some-song-id', 'another-song-id'])
sptfy.playlists.add_to('awesome-playlist-id', songs=['song-1-id', 'song-2-id'])
sptfy.playlists.remove_from('awesome-playlist_id', songs=['song-1-id'])

# Current user information
user_albums = sptfy.user.albums()
user_tracks = sptfy.user.tracks()
user_playlists = sptfy.user.playlists()
user_profile = sptfy.user.profile()
```

### Transformers

```Python
@sptfy.transform('tracks.get')
def get_track_name_and_artist(api_response):
    return (api_response['name'], api_response['artists'][0]['name'])

name, artist_name = sptfy.tracks.get('some-track')
```
