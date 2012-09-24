from django.conf import settings
from django.contrib import auth
from django.utils import translation

from piplmesh import urls
from piplmesh.frontend import tasks

def global_vars(request):
    """
    Adds global context variables to the context.
    """

    return {
        # Constants
        'HOME_CHANNEL_ID': tasks.HOME_CHANNEL_ID,
        'LOGIN_REDIRECT_URL': settings.LOGIN_REDIRECT_URL,
        'REDIRECT_FIELD_NAME': auth.REDIRECT_FIELD_NAME,
        'SEARCH_ENGINE_UNIQUE_ID': settings.SEARCH_ENGINE_UNIQUE_ID,
        'API_NAME': urls.API_NAME,

        # Variables
        'logo_url': "piplmesh/images/logo-%s.png" % translation.get_language(),
        'request_get_next': request.REQUEST.get(auth.REDIRECT_FIELD_NAME),
    }
