import json
import requests
from django.contrib.auth.models import User
from oauth2_login.signals import user_created_via_oauth2
from oauth2_login.models import *

class IdentityAlreadyClaimed(Exception):
    pass


def get_profile(url):
    return json.loads(requests.get(url).content)

def _extract_user_details(oauth2_response):
    email = fullname = first_name = last_name = None
    access_token = oauth2_response['access_token']
    profile = get_profile('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s' % access_token)
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

    return dict(email=email, first_name=first_name,
        last_name=last_name, fullname=fullname, apps_domain=apps_domain)

def update_user_details(user, details):
    updated = False
    if details.get('first_name'):
        user.first_name = details['first_name']
        updated = True
    if details.get('last_name'):
        user.last_name = details['last_name']
        updated = True
    if details.get('email'):
        user.email = details['email']
        user.username = details['email']
        updated = True

    if updated:
        user.save()

def associate_oauth2(user, oauth2_response):
    try:
        user_oauth2 = UserOauth2.objects.get(
            claimed_id__exact=oauth2_response.get('access_token'))
    except UserOauth2.DoesNotExist:
        user_oauth2 = UserOauth2.objects.create(user=user,
            claimed_id=oauth2_response.get('access_token'),
            display_id=oauth2_response.get('id_token').get('id'))
    else:
        if user != user_oauth2.user:
            raise IdentityAlreadyClaimed(
                "The identity %s has already been claimed"
                % oauth2_response.get('id_token').get('id'))

    return user_oauth2


def create_user_from_oauth2(oauth2_response):
    details = _extract_user_details(oauth2_response)
    email = details.get('email')
    if email in [None, '']:
        return None

    username = email
    # Pick a username for the user based on their nickname,
    # checking for conflicts.
    try:
        user = User.objects.get(username__exact=username)
        update_user_details(user, details)
        associate_oauth2(user, oauth2_response)
        return user
    except User.DoesNotExist:
        #apps_domain = email.split("@")[-1]
        #client = Client.get(apps_domain = apps_domain)
        # if client is not None:
        #    return None
        user = User.objects.create_user(username, email, password=None)
        update_user_details(user, details)
        associate_oauth2(user, oauth2_response)
        user_created_via_oauth2.send(sender=User, instance=user)
        return user
    else:
        return None

