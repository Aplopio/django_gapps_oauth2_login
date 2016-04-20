import json

from django.conf import settings
from django.http import (
    HttpResponseBadRequest)
from django.shortcuts import render_to_response
from oauth2client import xsrfutil
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.django_orm import Storage
from oauth2client.client import FlowExchangeError

from .service import (
    get_or_create_user_from_oauth2, redirect_to_authorize_url)
from .utils import function_importer
from .models import *


constructor_kwargs = {
    'redirect_uri': getattr(settings, "GAPPS_REDIRECT_URI", None),
    'auth_uri': getattr(settings, "GAPPS_AUTH_URI", None),
    'token_uri': getattr(settings, "GAPPS_TOKEN_URI", None),
    'access_type': 'online',
    'client_id': getattr(settings, "GAPPS_CLIENT_ID", None),
    'client_secret': getattr(settings, "GAPPS_CLIENT_SECRET", None),
    'scope': getattr(settings, "GAPPS_SCOPE", None)
}

FLOW = OAuth2WebServerFlow(**constructor_kwargs)


def login_begin(request):
    storage = Storage(CredentialsModel, 'id', request.user.id, 'credential')
    credential = storage.get()
    domain = request.REQUEST.get('domain')
    action = request.REQUEST.get('action')

    if credential is None or credential.invalid is True:
        return redirect_to_authorize_url(request, FLOW, domain, action)
    else:
        oauth2_response = credential.token_response
        if oauth2_response.get('id_token').get('hd') != domain:
            return redirect_to_authorize_url(request, FLOW, domain)

        email = oauth2_response.get('id_token').get('email')
        details = dict(email=email, apps_domain=domain, action=action)
        user = function_importer(settings.GAPPS_USER_FUNCTION)(**details)
        return function_importer(settings.GAPPS_LOGIN_SUCCESS_HANDLER)(user)


def auth_required(request):
    if not request.REQUEST.get('state'):
        return HttpResponseBadRequest('state parameter is '
                                      'required')

    if not xsrfutil.validate_token(settings.SECRET_KEY,
                                   request.REQUEST['state'],
                                   request.user):
        return HttpResponseBadRequest('Who are you? Access Denied!')

    try:
        credential = FLOW.step2_exchange(request.REQUEST)
    except FlowExchangeError, e:
        return HttpResponseBadRequest('Access Denied:' + e.message)

    oauth2_response = credential.token_response
    user = get_or_create_user_from_oauth2(oauth2_response,
                                          request.REQUEST.get('action'))

    if isinstance(user, dict):
        if user.get('error'):
            return HttpResponseBadRequest(user.get('error'))
        elif user.get('errorpage'):
            return render_to_response(user.get('errorpage'))

    if not user:
        return HttpResponseBadRequest("Access Denied!"
                                      " We couldn't find"
                                      " an active user for this"
                                      " account in the system")

    storage = Storage(CredentialsModel, 'id', user, 'credential')
    storage.put(credential)

    return function_importer(settings.GAPPS_LOGIN_SUCCESS_HANDLER)(user)
