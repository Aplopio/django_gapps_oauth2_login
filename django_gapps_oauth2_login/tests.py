from django.utils import unittest
from django.http import HttpRequest
from django_gapps_oauth2_login.views import *
from django.conf import settings

from django_gapps_oauth2_login.oauth2_utils import update_user_details, associate_oauth2, IdentityAlreadyClaimed
from django_gapps_oauth2_login.oauth2_utils import get_or_create_user_from_oauth2, _extract_user_details, get_profile
from django_gapps_oauth2_login.signals import user_created_via_oauth2, redirect_user_loggedin_via_oauth2
from mock import patch

import django_gapps_oauth2_login
user_created_via_oauth2.receivers = []
redirect_user_loggedin_via_oauth2.receivers = []

class TestGappsOauth2Login(unittest.TestCase):

    def test_singnal_sent(self):
        def dummy_signal_receiver(sender, instance, **kwargs):
            # check if received expected string
            assert instance=='test__323_string'

        user_created_via_oauth2.connect(dummy_signal_receiver, dispatch_uid='dummy_signal_receiver')
        user_created_via_oauth2.send(sender=User, instance='test__323_string')

    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_new_user_created_signal_sent(self, mock_extract_user_details):
        def new_user_created_sig_receiver(sender, instance, **kwargs):
            user = instance
            assert user.first_name == 'Vivek'
            assert user.last_name == 'Chand'
            assert user.username == 'vivek.chand@abcd.com'
            # Do whatever you want!

        user_created_via_oauth2.connect(new_user_created_sig_receiver, dispatch_uid='new_user_created_sig_receiver')
        mock_extract_user_details.return_value = {'first_name': 'Vivek',
                'last_name': 'Chand',
                'email':'vivek.chand@abcd.com'}
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        user.delete()

    def test_oauth2_login_url_provided(self):
        pass

    def test_oauth2_callback_url_provided(self):
        pass

    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    def test_extract_user_details(self, mock_requests_get):
        mock_requests_get.return_value = {'name':'Vivek Chand', 'email': 'vivek.chand@abcd.com', 'hd':'abcd.com'}
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        details = _extract_user_details(oauth2_response)
        expected_details = {'apps_domain': 'abcd.com',
                            'fullname': 'Vivek Chand',
                            'last_name': 'Chand',
                            'first_name': 'Vivek',
                            'email': 'vivek.chand@abcd.com'
                           }
        self.assertEqual(details, expected_details)

    # http://alexmarandon.com/articles/python_mock_gotchas/
    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_create_user_from_oauth2_case1(self, mock_extract_user_details):
        mock_extract_user_details.return_value = {'first_name': 'vivek',
                'last_name': 'chand',
                'email':'vivek.chand@abcd.com'}
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        user.delete()

    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_create_user_from_oauth2_case2(self, mock_extract_user_details):
        mock_extract_user_details.return_value = {'first_name': 'vivek',
                'last_name': 'chand',
                'email':'vivek.chand@abcd.com'}
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        user = get_or_create_user_from_oauth2(oauth2_response)
        user = get_or_create_user_from_oauth2(oauth2_response)
        user = get_or_create_user_from_oauth2(oauth2_response)
        user.delete()

    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_create_user_from_oauth2_case3(self, mock_extract_user_details):
        mock_extract_user_details.return_value = {'first_name': 'vivek',
                'last_name': 'chand'}
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_create_user_from_oauth2_case3(self, mock_extract_user_details):
        mock_extract_user_details.return_value = { 'first_name': 'vivek',
                'last_name': 'chand', 'email': '' }
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    def test_associate_oauth2_case1(self):
        user = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        associate_oauth2(user, oauth2_response)
        user_oauth2 = UserOauth2.objects.get(claimed_id__exact=oauth2_response.get('access_token'))
        self.assertEqual(user, user_oauth2.user)
        user_oauth2.user.delete()

    def test_associate_oauth2_case2(self):
        user1 = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        user2 = User.objects.create(first_name='vivek', last_name='chand', username='vivek.chand@abcd.com')

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        user_oauth2 = UserOauth2.objects.create( user=user1, claimed_id=oauth2_response.get('access_token'),
                    display_id=oauth2_response.get('id_token').get('id') )

        try:
            associate_oauth2(user2, oauth2_response)
        except IdentityAlreadyClaimed, e:
            self.assertEqual(e.message, 'The identity 42342423432423 has already been claimed')
            user1.delete()
            user2.delete()

    def test_associate_oauth2_case3(self):
        user1 = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        user2 = User.objects.create(first_name='vivek', last_name='chand', username='vivek.chand@abcd.com')

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        associate_oauth2(user1, oauth2_response)

        try:
            associate_oauth2(user2, oauth2_response)
        except IdentityAlreadyClaimed, e:
            self.assertEqual(e.message, 'The identity 42342423432423 has already been claimed')
            user1.delete()
            user2.delete()

    def test_update_user_details_case1(self):
        user = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        details = {'first_name': 'vivek', 'last_name': 'chand', 'email':'vivek.chand@abcd.com'}
        update_user_details(user, details)
        self.assertEqual(user.first_name, 'vivek')
        self.assertEqual(user.last_name, 'chand')
        self.assertEqual(user.username, 'vivek.chand@abcd.com')
        user.delete()

    def test_update_user_details_case2(self):
        user = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        details = {'first_name': 'vivek', 'last_name': 'chand'}
        update_user_details(user, details)
        self.assertEqual(user.first_name, 'vivek')
        self.assertEqual(user.last_name, 'chand')
        self.assertEqual(user.username, 'ram.lal@abcd.com')
        user.delete()

    def test_update_user_details_case3(self):
        user = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        details = {}
        update_user_details(user, details)
        self.assertEqual(user.first_name, 'ram')
        self.assertEqual(user.last_name, 'lal')
        self.assertEqual(user.username, 'ram.lal@abcd.com')
        user.delete()

    def test_make_a_request(self):
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': settings.SECRET_KEY
        }
        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        request.user = user

        redirect_resp = login_begin(request)
        bad_response = auth_required(request)

