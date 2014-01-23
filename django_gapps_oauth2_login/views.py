import json
import os
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest


from oauth2client import xsrfutil
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.django_orm import Storage
from oauth2client.client import FlowExchangeError

from django_gapps_oauth2_login.signals import redirect_user_loggedin_via_oauth2
from django_gapps_oauth2_login.oauth2_utils import get_or_create_user_from_oauth2, redirect_to_authorize_url
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
    domain = request.REQUEST.get('domain')
    if not domain:
        return HttpResponseBadRequest('OAuth2 Login Error: Google Apps Domain Not Sepcified')

    if credential is None or credential.invalid == True:
        return redirect_to_authorize_url(request, FLOW, domain)
    else:
        oauth2_response = credential.token_response
        if oauth2_response.get('id_token').get('hd') != domain:
            return redirect_to_authorize_url(request, FLOW, domain)

        user_oauth2 = UserOauth2.objects.get(
            google_id__exact=oauth2_response.get('id_token').get('id'))

        user = user_oauth2.user

        # Django Signals: Both send() and send_robust() return a list of tuple pairs [(receiver, response), ... ],
        # representing the list of called receiver functions and their response values.
        # https://docs.djangoproject.com/en/dev/topics/signals/#sending-signals
        return redirect_user_loggedin_via_oauth2.send(sender=User, instance=user)[0][1]

def auth_required(request):
    if not xsrfutil.validate_token(settings.SECRET_KEY, request.REQUEST['state'],
                                 request.user):
        return  HttpResponseBadRequest('Who are you? Access Denied!')

    try:
        credential = FLOW.step2_exchange(request.REQUEST)
    except FlowExchangeError, e:
        return HttpResponseBadRequest('Access Denied:' + e.message)

    oauth2_response = credential.token_response

    user = get_or_create_user_from_oauth2( oauth2_response )
    if not user:
        return  HttpResponseBadRequest('Access Denied! You are not authenticated as a Google Apps user.')

    storage = Storage(CredentialsModel, 'id', user, 'credential')
    storage.put(credential)

    return redirect_user_loggedin_via_oauth2.send(sender=User, instance=user)[0][1]

