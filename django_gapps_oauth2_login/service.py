from django.conf import settings
from django_gapps_oauth2_login.models import *
from django.http import HttpResponseRedirect
from oauth2client import xsrfutil
from oauth2client.client import AccessTokenCredentials
from BeautifulSoup import BeautifulSoup

import utils


def get_or_create_user_from_oauth2(oauth2_response):
    details = utils._extract_user_details(oauth2_response)
    if not details:
        return None

    user = function_importer(settings.GAPPS_USER_FUNCTION)(**details)
    if user:
        utils.associate_oauth2(user, oauth2_response)
    return user


def redirect_to_authorize_url(request, FLOW, domain):
    FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                   request.user)
    FLOW.params['hd'] = domain
    authorize_url = FLOW.step1_get_authorize_url()
    return HttpResponseRedirect(authorize_url)


def get_organization_name(admin_user, domain):
    http = get_authorized_http(admin_user)
    url = 'https://apps-apis.google.com/a/feeds/domain/2.0/'
    '%s/general/organizationName?key=%s' % (domain, settings.GAPPS_CLIENT_ID)
    response = authorized_request(admin_user, url)
    organization_name = utils._get_organization_name(response)
    return organization_name
