from urllib.parse import urlencode, quote
import pytest
import responses

import sptfy.oauth as oauth
from sptfy.clients import Spotify

