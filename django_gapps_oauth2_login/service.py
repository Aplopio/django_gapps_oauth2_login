from __future__ import absolute_import
from django.conf import settings
from django.http import HttpResponseRedirect
from oauth2client import xsrfutil

from . import utils


def get_or_create_user_from_oauth2(oauth2_response, action=None):
    details = utils._extract_user_details(oauth2_response)
    if details.get('error'):
        return details

    if action:
        details['action'] = action

    user = utils.function_importer(settings.GAPPS_USER_FUNCTION)(**details)
    return user


def redirect_to_authorize_url(request, FLOW, domain, action=None):
    FLOW.params['state'] = xsrfutil.generate_token(settings.SECRET_KEY,
                                                   request.user)
    if domain:
        FLOW.params['hd'] = domain

    FLOW.redirect_uri = u'{}?action={}'.\
        format(settings.GAPPS_REDIRECT_URI, action) if action \
        else settings.GAPPS_REDIRECT_URI

    authorize_url = FLOW.step1_get_authorize_url()
    return HttpResponseRedirect(authorize_url)


def get_organization_name(admin_user, domain):
    url = 'https://apps-apis.google.com/a/feeds/domain/2.0/%s/general/organizationName?key=%s' % (
        domain, settings.GAPPS_CLIENT_ID)
    response = utils.authorized_request(admin_user, url)
    if response:
        organization_name = utils._get_organization_name(response)
        return organization_name.strip() if organization_name else None
