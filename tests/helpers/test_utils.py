from urllib.parse import quote, urlencode

import responses


# Add some utilities on responses later
def search_params(
    search_term: str,
    item_type: str
) -> str:
    search_query = {
        'q': quote(search_term), 
        'type': item_type,
    }
    return urlencode(search_query)

