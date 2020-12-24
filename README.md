
# Sptfy: An ergonomic and easy to remember Spotify Web API client

*This library is currently a work in progress. Some APIs are not well defined yet and some part of the design is not completely finished*

## Usage

The API follows the idea that the methods should follow an easy to remember pattern so the user doesn't have to keep pulling up documentation in order to discover how to achieve what it wants.

The API also tries to map to how the endpoints are organized in the Spotify Web API so that it's simple to find documentation about the API usage, but this rule is not followed in some places.

```Python
from sptfy.sync import Spotify

# Allows configuration to be done, but does not initiates authentication immediately
# Authentication is done on the first call to the API (but this might change)
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

Transfomers allow the user to manipulate the response from the API in order to work with a more manageable data structure. Sometimes the API returns more information than what the user needs, a transformer allows it to use only the subsection of data that it's important for the task at hand.

```Python
sptfy = Spotify()

# Register a transfomer
@sptfy.transformer('tracks.search')
def get_track_result_names(api_response):
    return [track['name'] for track in api_response['tracks']['items']]

# Receives a list of track names instead of json object
track_names = sptfy.tracks.search('The Good Song')
for name in track_names:
  print(name)

# Temporarily disables current transformers
with sptfy.disable_transformers():
  json_response = sptfy.tracks.search('The Good Song')

# The result will now be a json object since the transformer was disabled
print(json_response['tracks']['items'])


# The transformer can also be specified explicitly and it will take 
# precedence over registered ones
def get_track_items(api_response):
  return api_response['tracks']['items']

track_items = sptfy.tracks.search('The Good Song', transformer=get_track_items)
for track_item in track_items:
    print(track_item)
```
