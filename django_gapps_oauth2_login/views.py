import json
import os
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest


from oauth2client import xsrfutil
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.django_orm import Storage

from django_gapps_oauth2_login.signals import redirect_user_loggedin_via_oauth2
from django_gapps_oauth2_login.oauth2_utils import create_user_from_oauth2
from django_gapps_oauth2_login.models import *


constructor_kwargs = {
    'redirect_uri': getattr(settings, "GAPPS_REDIRECT_URI", None),
    'auth_uri': getattr(settings, "GAPPS_AUTH_URI", None),
    'token_uri': getattr(settings, "GAPPS_TOKEN_URI", None),
    'access_type' : 'online'
}

FLOW = OAuth2WebServerFlow(
        client_id=getattr(settings, "GAPPS_CLIENT_ID", None),
        client_secret=getattr(settings, "GAPPS_CLIENT_SECRET", None),
        scope=getattr(settings, "GAPPS_SCOPE", None),
        **constructor_kwargs
        )

def login_begin(request):
    storage = Storage(CredentialsModel, 'id', request.user.id, 'credential')
    credential = storage.get()

    if credential is None or credential.invalid == True:
        FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                   request.user)
        authorize_url = FLOW.step1_get_authorize_url()
        return HttpResponseRedirect(authorize_url)
    else:
        oauth2_response = credential.token_response
        user_oauth2 = UserOauth2.objects.get(
            claimed_id__exact=oauth2_response.get('access_token'))

        user = user_oauth2.user

        # Django Signals: Both send() and send_robust() return a list of tuple pairs [(receiver, response), ... ],
        # representing the list of called receiver functions and their response values.
        # https://docs.djangoproject.com/en/dev/topics/signals/#sending-signals
        return redirect_user_loggedin_via_oauth2.send(sender=User, instance=user)[0][1]

def auth_required(request):
    if not xsrfutil.validate_token(settings.SECRET_KEY, request.REQUEST['state'],
                                 request.user):
        return  HttpResponseBadRequest('Who are you?')

    error = request.get('error')
    if error not in [None, ''] and error=='access_denied':
        return  HttpResponseBadRequest('Access Denied!')

    credential = FLOW.step2_exchange(request.REQUEST)

    user = create_user_from_oauth2( credential.token_response )

    storage = Storage(CredentialsModel, 'id', user, 'credential')
    storage.put(credential)

    return redirect_user_loggedin_via_oauth2.send(sender=User, instance=user)[0][1]

