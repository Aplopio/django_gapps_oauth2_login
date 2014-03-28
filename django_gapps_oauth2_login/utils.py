import json
import requests
from .models import CredentialsModel, UserOauth2
from .exceptions import IdentityAlreadyClaimed

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


def get_access_token(user):
    cred = CredentialsModel.objects.get(id=admin_user)
    google_id = UserOauth2.objects.get(user=admin_user).google_id
    access_token = cred.credential.token_response.get('access_token')
    return access_token


def authorized_request(user):
    access_token = get_access_token(user)
    credentials = AccessTokenCredentials(access_token, 'my-user-agent/1.0')
    http = httplib2.Http()
    http = credentials.authorize(http)
    return http

def _get_organization_name(response):
    xml_string = user_resp[1]
    soup = BeautifulSoup(xml_string)
    organization_name = soup.findChildren()[-1].get('value')
    return organization_name
