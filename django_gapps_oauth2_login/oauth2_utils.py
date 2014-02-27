import json
import requests
from django.conf import settings
from django_gapps_oauth2_login.models import *
from django.http import HttpResponseRedirect
from oauth2client import xsrfutil
from django.utils import importlib


def function_importer(func):
    if callable(func):
        return func
    else:
        module_bits = func.split('.')
        module_path, func_name = '.'.join(module_bits[:-1]), module_bits[-1]
        module = importlib.import_module(module_path)
        func = getattr(module, func_name, None)
        return func


class IdentityAlreadyClaimed(Exception):
    pass


def get_profile(url):
    return json.loads(requests.get(url).content)


def _extract_user_details(oauth2_response):
    email = fullname = first_name = last_name = None
    access_token = oauth2_response['access_token']
    profile = get_profile('https://www.googleapis.com/oauth2/v1/'
                          'userinfo?alt=json&access_token=%s' % access_token)
    fullname = profile.get('name')
    email = profile.get('email')
    if ' ' in fullname:
        # Django wants to store first and last names separately,
        # so we do our best to split the full name.
        first_name, last_name = fullname.rsplit(None, 1)
    else:
        first_name = u''
        last_name = fullname
    apps_domain = profile.get('hd')

    if not apps_domain:
        return None

    return dict(email=email, first_name=first_name,
                last_name=last_name, fullname=fullname,
                apps_domain=apps_domain)


def associate_oauth2(user, oauth2_response):
    try:
        user_oauth2 = UserOauth2.objects.get(
            google_id__exact=oauth2_response.get('id_token').get('id'))
    except UserOauth2.DoesNotExist:
        user_oauth2 = UserOauth2.objects.create(user=user,
                                                google_id=oauth2_response.
                                                get('id_token').get('id'))
    else:
        if user != user_oauth2.user:
            raise IdentityAlreadyClaimed(
                "The identity %s has already been claimed"
                % oauth2_response.get('id_token').get('id'))

    return user_oauth2


def get_or_create_user_from_oauth2(oauth2_response):
    details = _extract_user_details(oauth2_response)
    if not details:
        return None

    user = function_importer(settings.GAPPS_USER_FUNCTION)(**details)
    if user:
        associate_oauth2(user, oauth2_response)
    return user


def redirect_to_authorize_url(request, FLOW, domain):
    FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                   request.user)
    FLOW.params['hd'] = domain
    authorize_url = FLOW.step1_get_authorize_url()
    return HttpResponseRedirect(authorize_url)
