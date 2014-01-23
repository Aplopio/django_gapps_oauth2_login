from django.utils import unittest
from django.http import HttpRequest
from django_gapps_oauth2_login.views import *
from django.conf import settings

from django_gapps_oauth2_login.oauth2_utils import update_user_details, associate_oauth2, IdentityAlreadyClaimed
from django_gapps_oauth2_login.oauth2_utils import get_or_create_user_from_oauth2, _extract_user_details, get_profile
from django_gapps_oauth2_login.oauth2_utils import redirect_to_authorize_url
from django_gapps_oauth2_login.signals import user_created_via_oauth2, redirect_user_loggedin_via_oauth2
from django.http import HttpResponseRedirect
from mock import patch

import oauth2client
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

    def test_settings_variables_defined(self):
        self.assertNotEqual(getattr(settings, "GAPPS_REDIRECT_URI", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_AUTH_URI", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_TOKEN_URI", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_CLIENT_ID", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_CLIENT_SECRET", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_SCOPE", None), None)


    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    def test_extract_user_details_case1(self, mock_requests_get):
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

    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    def test_extract_user_details_case2(self, mock_requests_get):
        mock_requests_get.return_value = {'name':'Vivek Chand', 'email': 'vivek.chand@gmail.com' }
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        details = _extract_user_details(oauth2_response)
        self.assertEqual(details, None)

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
    def test_create_user_from_oauth2_case4(self, mock_extract_user_details):
        mock_extract_user_details.return_value = { 'first_name': 'vivek',
                'last_name': 'chand', 'email': '' }
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    @patch.object(django_gapps_oauth2_login.oauth2_utils, '_extract_user_details')
    def test_create_user_from_oauth2_case5(self, mock_extract_user_details):
        mock_extract_user_details.return_value = None
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    def test_associate_oauth2_case1(self):
        user = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        associate_oauth2(user, oauth2_response)
        user_oauth2 = UserOauth2.objects.get(google_id__exact=oauth2_response.get('id_token').get('id'))
        self.assertEqual(user, user_oauth2.user)
        user_oauth2.user.delete()

    def test_associate_oauth2_case2(self):
        user1 = User.objects.create(first_name='ram', last_name='lal', username='ram.lal@abcd.com')
        user2 = User.objects.create(first_name='vivek', last_name='chand', username='vivek.chand@abcd.com')

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        user_oauth2 = UserOauth2.objects.create( user=user1, google_id=oauth2_response.get('id_token').get('id') )

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

    def test_login_begin_redirect(self):
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'domain': 'vivekchand.info'
        }
        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()
        request.user = user
        auth_redirect_response = login_begin(request)
        self.assertEqual(auth_redirect_response.status_code, 302)
        self.assertTrue('https://accounts.google.com/o/oauth2/auth?state=' in auth_redirect_response.get('Location'))
        user.delete()

    @patch.object(oauth2client.django_orm.Storage, 'get')
    def test_login_begin_has_credential(self, mock_get):
        def redirect_user_loggedin_via_oauth2_recvr(sender, instance, **kwargs):
            user = instance
            # Do whatever you want!
            return HttpResponseRedirect('/somewhere')

        redirect_user_loggedin_via_oauth2.connect( redirect_user_loggedin_via_oauth2_recvr, dispatch_uid='redirect_signal')

        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        user_oauth2 = UserOauth2.objects.create( user=user, google_id=oauth2_response.get('id_token').get('id') )

        class credential:
            token_response = oauth2_response
            invalid = False

        mock_get.return_value = credential()
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'domain': 'vivekchand.info'
        }
        request.user = user
        redirect_response = login_begin(request)

        self.assertEqual(redirect_response.status_code, 302)
        self.assertTrue(redirect_response.get('Location'), '/somewhere')

        user.delete()


    def test_auth_required_error(self):
        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.GET = {
            'error':'access_denied',
        }
        request.user = user
        response = auth_required(request)

        self.assertEqual(response.content, 'Access Denied:No code was supplied in the query parameters.')
        self.assertEqual(response.status_code, 400)

        user.delete()

    def test_auth_required_invalid_state(self):
        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': 'abcd',
        }

        request.user = user
        response = auth_required(request)

        self.assertEqual(response.content, 'Who are you? Access Denied!')
        self.assertEqual(response.status_code, 400)

        user.delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    def test_auth_required_get_or_create_throws_None(self, mock_requests_get, mock_step2_exchange):
        mock_requests_get.return_value = {'name':'Vivek Chand', 'email': 'vivek.chand@abcd.com'}
        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}
        user_oauth2 = UserOauth2.objects.create( user=user, google_id=oauth2_response.get('id_token').get('id') )

        class credential:
            token_response = oauth2_response
            invalid = False

        mock_step2_exchange.return_value = credential()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        response = auth_required(request)

        self.assertEqual(response.content, 'Access Denied! You are not authenticated as a Google Apps user.')
        self.assertEqual(response.status_code, 400)

        user_oauth2.delete()
        user.delete()


    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    @patch.object(oauth2client.django_orm.Storage, 'put')
    def test_successful_redirect_with_user_creation(self, mock_storage_put, mock_requests_get, mock_step2_exchange):
        def new_user_created_sig_receiver(sender, instance, **kwargs):
            user = instance
            assert user.first_name == 'Vivek'
            assert user.last_name == 'Chand'
            assert user.username == 'vivek.chand@abcd.com'
            # Do whatever you want!

        def redirect_user_loggedin_via_oauth2_recvr(sender, instance, **kwargs):
            user = instance
            # Do whatever you want!
            return HttpResponseRedirect('/somewhere')

        redirect_user_loggedin_via_oauth2.connect( redirect_user_loggedin_via_oauth2_recvr, dispatch_uid='redirect_signal')
        user_created_via_oauth2.connect(new_user_created_sig_receiver, dispatch_uid='new_user_created_sig_receiver')

        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        mock_requests_get.return_value = {'name':'Vivek Chand', 'email': 'vivek.chand@abcd.com', 'hd': 'abcd.com'}

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        class credential:
            token_response = oauth2_response
            invalid = False

        mock_step2_exchange.return_value = credential()

        response = auth_required(request)
        self.assertEqual(response.get('Location'), '/somewhere')
        self.assertEqual(response.status_code, 302)

        user.delete()
        User.objects.get(username='vivek.chand@abcd.com').delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.oauth2_utils, 'get_profile')
    @patch.object(oauth2client.django_orm.Storage, 'put')
    def test_raise_flow_exchange_error(self, mock_storage_put, mock_requests_get, mock_step2_exchange):
        def new_user_created_sig_receiver(sender, instance, **kwargs):
            user = instance
            assert user.first_name == 'Vivek'
            assert user.last_name == 'Chand'
            assert user.username == 'vivek.chand@abcd.com'
            # Do whatever you want!

        def redirect_user_loggedin_via_oauth2_recvr(sender, instance, **kwargs):
            user = instance
            # Do whatever you want!
            return HttpResponseRedirect('/somewhere')

        redirect_user_loggedin_via_oauth2.connect( redirect_user_loggedin_via_oauth2_recvr, dispatch_uid='redirect_signal')
        user_created_via_oauth2.connect(new_user_created_sig_receiver, dispatch_uid='new_user_created_sig_receiver')

        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        mock_requests_get.return_value = {'name':'Vivek Chand', 'email': 'vivek.chand@abcd.com', 'hd': 'abcd.com'}

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},  'and_some_more': 'blah_blah_blah'}

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        class credential:
            token_response = oauth2_response
            invalid = False

        def side_effect(arg):
            raise FlowExchangeError('invalid_token')
        mock_step2_exchange.side_effect = side_effect

        response = auth_required(request)

        self.assertEqual(response.content, 'Access Denied:invalid_token')
        self.assertEqual(response.status_code, 400)

        user.delete()


    def test_no_domain_specified(self):
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

        bad_resp = login_begin(request)
        self.assertEqual(bad_resp.content, 'OAuth2 Login Error: Google Apps Domain Not Sepcified')
        self.assertEqual(bad_resp.status_code, 400)
        user.delete()


    def test_make_a_bad_request(self):
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

        bad_response = login_begin(request)
        self.assertEqual(bad_response.content, 'OAuth2 Login Error: Google Apps Domain Not Sepcified')
        self.assertEqual(bad_response.status_code, 400)
        bad_response = auth_required(request)

        self.assertEqual(bad_response.content, 'Who are you? Access Denied!')
        self.assertEqual(bad_response.status_code, 400)

        user.delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step1_get_authorize_url')
    def test_redirect_to_authorize_url(self, mock_step1_get_authorize_url):
        mock_step1_get_authorize_url.return_value = 'http://www.go_to_google.com/and/authenticate/and/come/back'
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

        domain = 'rajnikanth.com'
        redirect_resp = redirect_to_authorize_url(request, FLOW, domain)
        self.assertEqual(redirect_resp.get('Location'), 'http://www.go_to_google.com/and/authenticate/and/come/back')
        self.assertEqual(redirect_resp.status_code, 302)
        user.delete()


    @patch.object(oauth2client.django_orm.Storage, 'get')
    def test_login_begin_has_credential_different_domain(self, mock_get):
        def redirect_user_loggedin_via_oauth2_recvr(sender, instance, **kwargs):
            user = instance
            # Do whatever you want!
            return HttpResponseRedirect('/somewhere')

        redirect_user_loggedin_via_oauth2.connect( redirect_user_loggedin_via_oauth2_recvr, dispatch_uid='redirect_signal')

        user = User(first_name='vivek', last_name='chand', username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423', 'hd':'rajnikanth.com'},  'and_some_more': 'blah_blah_blah'}
        user_oauth2 = UserOauth2.objects.create( user=user, google_id=oauth2_response.get('id_token').get('id') )

        class credential:
            token_response = oauth2_response
            invalid = False

        mock_get.return_value = credential()
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.REQUEST = {
            'domain': 'vivekchand.info'
        }
        request.user = user
        redirect_response = login_begin(request)

        self.assertEqual(redirect_response.status_code, 302)
        self.assertTrue('https://accounts.google.com/o/oauth2/auth?state=' in redirect_response.get('Location'))

        user.delete()

