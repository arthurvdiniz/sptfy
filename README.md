
# Sptfy: An ergonomic and easy to remember Spotify Web API client

*This library is currently a work in progress. Some APIs are not well defined yet and some part of the design is not completely finished*

## Usage

The API follows the idea that the methods should follow an easy to remember pattern so the user doesn't have to keep pulling up documentation in order to discover how to achieve what it wants.

The API also tries to map to how the endpoints are organized in the Spotify Web API so that it's simple to find documentation about the API usage, but this rule is not followed in some places.

```Python
from sptfy.clients import Spotify

# Allows configuration to be done, but does not initiates authentication immediately
# Authentication is done on the first call to the API (but this might change)
sptf = Spotify()

# Retrieves an Spotify track (i.e. song)
track = sptf.tracks.get('track-id')
playlist = sptf.playlists.get('playlist-id')
album = sptf.albums.get('album-id')
artist = sptf.artists.get('artist-id')

# Searching
track = sptf.tracks.search('Feel Good Inc.')
playlist = sptf.playlists.search('Best of 2019')
album = sptf.albums.search('To Pimp a Butterfly')
artist = sptf.artists.search('Snarky Puppy')

# Playlist manipulation
sptf.playlists.create('My Awesome Playlist', songs=['some-song-id', 'another-song-id'])
sptf.playlists.add_to('awesome-playlist-id', songs=['song-1-id', 'song-2-id'])
sptf.playlists.remove_from('awesome-playlist_id', songs=['song-1-id'])

# Current user information
user_albums = sptf.user.albums()
user_tracks = sptf.user.tracks()
user_playlists = sptf.user.playlists()
user_profile = sptf.user.profile()

# Audio Analysis
features = sptfy.tracks.audio_features('track-id')
analysis = sptfy.tracks.audio_analysis('track-id')
```

### Transformers

Transfomers allow the user to manipulate the response from the API in order to work with a more manageable data structure. Sometimes the API returns more information than what the user needs, a transformer allows it to use only the subsection of data that it's important for the task at hand.

```Python
sptf = Spotify()

# Register a transfomer
@sptf.transformer('tracks.search')
def get_track_result_names(api_response):
    return [track['name'] for track in api_response['tracks']['items']]

# Receives a list of track names instead of json object
track_names = sptf.tracks.search('The Good Song')
for name in track_names:
  print(name)

# Temporarily disables current transformers
with sptf.disable_transformers():
  json_response = sptf.tracks.search('The Good Song')

# The result will now be a json object since the transformer was disabled
print(json_response['tracks']['items'])


# The transformer can also be specified explicitly and it will take 
# precedence over registered ones
def get_track_items(api_response):
  return api_response['tracks']['items']

track_items = sptf.tracks.search('The Good Song', transformer=get_track_items)
for track_item in track_items:
    print(track_item)
```

### Configuration

The library aims to be flexible enough to be used in various environments (i.e. flask, django, CLI), even though this is not the case at the moment.

The default configuration does the authorization by opening a web browser so that the client is easily usable from a interactive python session.

```Python
import sptfy.oauth as oauth
from sptfy.oauth import Scope

# The default configuration uses:
# OAuth flow: Authorization Code
# Authorization: terminal prompt for the response code
# Token Cache: None
# Client Credentials: from environment variables
sptf = Spotify()

# client credentials can be defined explicitly
client_id = os.getenv('SPTFY_CLIENT_ID')
client_secret = os.getenv('SPTFY_CLIENT_SECRET')
redirect_url = os.getenv('SPTFY_REDIRECT_URL')
scopes = [Scope.USER_LIBRARY_MODIFY, Scope.USER_LIBRARY_READ]
# or
scopes = ['user-library-modify', 'user-library-read']
credentials = oauth.ClientCredentials(
  client_id, 
  client_secret, 
  redirect_url,
  scopes=scopes
)

# or can be obtained from the environment
credentials = oauth.ClientCredentials.from_env_variables()
credentials.scopes = scopes

# OAuth Managers
oauth_manager = oauth.AuthorizationCodeFlow(credentials)
# or
oauth_manager = oauth.ClientCredentialsFlow(credentials)

custom_sptf = Spotify(oauth_manager)

# Ideally the oauth managers would work with third party APIs in backend environments, 
# but this is still in the design phase.
```
