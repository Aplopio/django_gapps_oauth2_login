import json

import requests
import httplib2
from oauth2client.client import AccessTokenCredentials
from django.utils import importlib
from BeautifulSoup import BeautifulSoup

from .models import CredentialsModel


def function_importer(func):
    if callable(func):
        return func
    else:
        module_bits = func.split('.')
        module_path, func_name = '.'.join(module_bits[:-1]), module_bits[-1]
        module = importlib.import_module(module_path)
        func = getattr(module, func_name, None)
        return func


def get_profile(url):
    try:
        content = requests.get(url).content
        return json.loads(content)

    # except requests.ConnectionError:
    #     return {
    #         'error': ('Access Denied! '
    #                   'There was a connection error when trying '
    #                   'to access the GApps profile')
    #     }
    #
    # except requests.HTTPError:
    #     return {
    #         'error': ('Access Denied!'
    #                   'The request to Google API returned an '
    #                   'invalid HTTP response')
    #     }
    #
    # except requests.Timeout:
    #     return {
    #         'error': ('Access Denied!'
    #                   'The connection timed out while trying '
    #                   'to access the GApps profile')
    #     }
    #
    # except requests.TooManyRedirects:
    #     return {
    #         'error': ('Access Denied!'
    #                   'The requests to the GApps profile '
    #                   'caused too many redirects')
    #     }

    except requests.RequestException:
        return {'error': ('Access Denied!'
                          'There was an unkown error when trying to '
                          'access the GApps profile.')}

    except ValueError:
        return {'error': ('Access Denied!'
                          'GApps returned an invalid response.')}

def _extract_user_details(oauth2_response):
    email = fullname = first_name = last_name = None
    access_token = oauth2_response['access_token']
    profile = get_profile('https://www.googleapis.com/oauth2/v1/'
                          'userinfo?alt=json&access_token=%s' % access_token)

    if profile.get('error'):
        return profile

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
        return {'error': ('Access Denied!'
                          ' You are not authenticated as'
                          ' a Google Apps user.')}

    return dict(email=email, first_name=first_name,
                last_name=last_name, fullname=fullname,
                apps_domain=apps_domain)


def get_access_token(user):
    try:
        cred = CredentialsModel.objects.get(id=user)
        access_token = cred.credential.token_response.get('access_token')
    except CredentialsModel.DoesNotExist:
        access_token = None
    return access_token


def do_request(authenticated_http, url):
    return authenticated_http.request(url)


def authorized_request(user, url):
    access_token = get_access_token(user)
    if access_token:
        credentials = AccessTokenCredentials(access_token, 'my-user-agent/1.0')
        http = httplib2.Http()
        http = credentials.authorize(http)
        response = do_request(http, url)
        return response


def _get_organization_name(response):
    xml_string = response[1]
    soup = BeautifulSoup(xml_string)
    organization_name = soup.findChildren()[-1].get('value')
    return organization_name
