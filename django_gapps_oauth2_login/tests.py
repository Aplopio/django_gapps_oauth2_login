from __future__ import absolute_import
from builtins import object
import  requests
import json
from django.test import TestCase
from django.http import HttpRequest
from django.conf import settings
from django.http import HttpResponseRedirect
from mock import patch, Mock, MagicMock
import oauth2client


from django_gapps_oauth2_login.views import *
from .utils import (_extract_user_details,
                    get_access_token, authorized_request, _get_organization_name)
from .service import \
    get_or_create_user_from_oauth2, get_organization_name
from .service import redirect_to_authorize_url
from .models import CredentialsModel
from . import utils
import django_gapps_oauth2_login


class TestGappsOauth2Login(TestCase):
    @patch.object(django_gapps_oauth2_login.utils,
                  '_extract_user_details')
    @patch(settings.GAPPS_USER_FUNCTION)
    def test_gapps_user_settings(self, gapps_user_function,
                                 mock_extract_user_details):
        dummy_user = User.objects.create(first_name='',
                                         last_name='',
                                         username='asdfasdf',
                                         email='asdf@email.com')
        gapps_user_function.return_value = dummy_user

        mock_extract_user_details.return_value = {
            'first_name': 'Vivek',
            'last_name': 'Chand',
            'email': 'vivek.chand@abcd.com'}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},
            'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, dummy_user)

    def test_settings_variables_defined(self):
        self.assertNotEqual(getattr(settings, "GAPPS_REDIRECT_URI", None),
                            None)
        self.assertNotEqual(getattr(settings, "GAPPS_AUTH_URI", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_TOKEN_URI", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_CLIENT_ID", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_CLIENT_SECRET", None),
                            None)
        self.assertNotEqual(getattr(settings, "GAPPS_SCOPE", None), None)
        self.assertNotEqual(getattr(settings, "GAPPS_USER_FUNCTION", None),
                            None)
        self.assertNotEqual(getattr(settings, "GAPPS_LOGIN_SUCCESS_HANDLER"),
                            None)

    @patch.object(django_gapps_oauth2_login.utils, 'get_profile')
    def test_extract_user_details_case1(self, mock_requests_get):
        mock_requests_get.return_value = {'name': 'Vivek Chand',
                                          'email': 'vivek.chand@abcd.com',
                                          'hd': 'abcd.com'}

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},
            'and_some_more': 'blah_blah_blah'}
        details = _extract_user_details(oauth2_response)
        expected_details = {'apps_domain': 'abcd.com',
                            'fullname': 'Vivek Chand',
                            'last_name': 'Chand',
                            'first_name': 'Vivek',
                            'email': 'vivek.chand@abcd.com'}
        self.assertEqual(details, expected_details)

    @patch.object(django_gapps_oauth2_login.utils, 'get_profile')
    def test_extract_user_details_case2(self, mock_requests_get):
        mock_requests_get.return_value = {
            'name': 'Vivek Chand',
            'email': 'vivek.chand@gmail.com'}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},
            'and_some_more': 'blah_blah_blah'}
        details = _extract_user_details(oauth2_response)
        self.assertTrue(details.get('error'))

    # http://alexmarandon.com/articles/python_mock_gotchas/
    @patch.object(django_gapps_oauth2_login.utils,
                  '_extract_user_details')
    @patch(settings.GAPPS_USER_FUNCTION)
    def test_create_user_from_oauth2_case1(self, gapps_user_function,
                                           mock_extract_user_details):
        mock_extract_user_details.return_value = {
            'first_name': 'vivek',
            'last_name': 'chand',
            'username': 'vivekchand',
            'email': 'vivek.chand@abcd.com'}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '4232342423432423'},
            'and_some_more': 'blah_blah_blah'}
        gapps_user_function.return_value = User.objects. \
            create(**mock_extract_user_details.return_value)
        user = get_or_create_user_from_oauth2(oauth2_response)
        user.delete()

    @patch.object(django_gapps_oauth2_login.utils,
                  '_extract_user_details')
    @patch(settings.GAPPS_USER_FUNCTION)
    def test_create_user_from_oauth2_case3(self, gapps_user_function,
                                           mock_extract_user_details):
        gapps_user_function.return_value = None
        mock_extract_user_details.return_value = {
            'first_name': 'vivek',
            'last_name': 'chand'}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},
            'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    @patch.object(django_gapps_oauth2_login.utils, '_extract_user_details')
    def test_create_user_from_oauth2_case4(self, mock_extract_user_details):
        mock_extract_user_details.return_value = {'first_name': 'vivek',
                                                  'last_name': 'chand', 'email': ''}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'}, 'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertEqual(user, None)

    @patch.object(django_gapps_oauth2_login.utils, '_extract_user_details')
    def test_create_user_from_oauth2_case5(self, mock_extract_user_details):
        mock_extract_user_details.return_value = {'error': 'bla bla'}
        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'}, 'and_some_more': 'blah_blah_blah'}

        user = get_or_create_user_from_oauth2(oauth2_response)
        self.assertTrue(user.get('error'))


    def test_login_begin_redirect(self):
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'domain': 'vivekchand.info'
        }
        user = User(first_name='vivek',
                    last_name='chand', username='vivek@rajnikanth.com', email='vivek@rajnikanth.com')
        user.save()
        request.user = user
        auth_redirect_response = login_begin(request)
        self.assertEqual(auth_redirect_response.status_code, 302)
        self.assertTrue('https://accounts.google.com/o/oauth2/auth?state=' in
                        auth_redirect_response.get('Location'))
        user.delete()

    @patch.object(oauth2client.django_orm.Storage, 'get')
    @patch(settings.GAPPS_LOGIN_SUCCESS_HANDLER)
    def test_login_begin_has_credential(self, login_success_handler, mock_get):
        login_success_handler.return_value = HttpResponseRedirect('/somewhere')

        user = User(first_name='vivek',
                    last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'},
            'and_some_more': 'blah_blah_blah'}

        class credential(object):
            token_response = oauth2_response
            invalid = False

        mock_get.return_value = credential()
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'domain': 'vivekchand.info'
        }
        request.user = user
        redirect_response = login_begin(request)

        self.assertEqual(redirect_response.status_code, 302)
        self.assertTrue(redirect_response.get('Location'), '/somewhere')

        user.delete()

    def test_auth_required_error(self):
        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.GET = {
            'error': 'access_denied',
        }
        request.user = user
        response = auth_required(request)

        self.assertEqual(
            response.content, 'Access Denied:No code was supplied in the query parameters.')
        self.assertEqual(response.status_code, 400)

        user.delete()

    def test_auth_required_missing_state(self):
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {}

        response = auth_required(request)

        self.assertEqual(response.content, 'state parameter is required')


    def test_auth_required_invalid_state(self):
        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': 'abcd',
        }

        request.user = user
        response = auth_required(request)

        self.assertEqual(response.content, 'Who are you? Access Denied!')
        self.assertEqual(response.status_code, 400)

        user.delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.utils, 'get_profile')
    def test_auth_required_get_or_create_throws_None(self, mock_requests_get, mock_step2_exchange):
        mock_requests_get.return_value = {
            'name': 'Vivek Chand', 'email': 'vivek.chand@abcd.com'}
        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423'}, 'and_some_more': 'blah_blah_blah'}

        class credential(object):
            token_response = oauth2_response
            invalid = False

        mock_step2_exchange.return_value = credential()

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        response = auth_required(request)

        self.assertEqual(response.status_code, 400)
        user.delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.utils, 'get_profile')
    @patch.object(oauth2client.django_orm.Storage, 'put')
    @patch(settings.GAPPS_USER_FUNCTION)
    @patch(settings.GAPPS_LOGIN_SUCCESS_HANDLER)
    def test_successful_redirect_with_user_creation(self, gapps_login_handler,
                                                    gapps_user_function,
                                                    mock_storage_put,
                                                    mock_requests_get,
                                                    mock_step2_exchange):
        gapps_login_handler.return_value = HttpResponseRedirect('/somewhere')

        user = User.objects.create(first_name='vivek', last_name='chand',
                                   username='vivek@rajnikanth.com')
        gapps_user_function.return_value = user

        mock_requests_get.return_value = {'name': 'Vivek Chand',
                                          'email': 'vivek.chand@abcd.com',
                                          'hd': 'abcd.com'}

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432443'},
            'and_some_more': 'blah_blah_blah'}

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        class credential(object):
            token_response = oauth2_response
            invalid = False

        mock_step2_exchange.return_value = credential()

        response = auth_required(request)
        self.assertEqual(response.get('Location'), '/somewhere')
        self.assertEqual(response.status_code, 302)
        user.delete()

    @patch.object(oauth2client.client.OAuth2WebServerFlow, 'step2_exchange')
    @patch.object(django_gapps_oauth2_login.utils, 'get_profile')
    @patch.object(oauth2client.django_orm.Storage, 'put')
    @patch(settings.GAPPS_USER_FUNCTION)
    @patch(settings.GAPPS_LOGIN_SUCCESS_HANDLER)
    def test_raise_flow_exchange_error(self, gapps_user_function,
                                       login_success_handler,
                                       mock_storage_put, mock_requests_get,
                                       mock_step2_exchange):
        user = User(first_name='vivek',
                    last_name='chand', username='vivek@rajnikanth.com')
        user.save()
        gapps_user_function.return_value = user
        login_success_handler.return_value = HttpResponseRedirect('/somewhere')

        mock_requests_get.return_value = {
            'name': 'Vivek Chand',
            'email': 'vivek.chand@abcd.com', 'hd': 'abcd.com'}

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '4234242342332423'},
            'and_some_more': 'blah_blah_blah'}

        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': xsrfutil.generate_token(settings.SECRET_KEY, user),
        }
        request.user = user

        class credential(object):
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
        request.GET = {
            'state': settings.SECRET_KEY
        }

        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()
        request.user = user

        resp = login_begin(request)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue('https://accounts.google.com/o/oauth2/auth?state=' in
                        resp.get('Location'))
        user.delete()

    def test_make_a_bad_request(self):
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'state': settings.SECRET_KEY
        }

        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()
        request.user = user

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
        request.GET = {
            'state': settings.SECRET_KEY
        }

        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()
        request.user = user

        domain = 'rajnikanth.com'
        redirect_resp = redirect_to_authorize_url(request, FLOW, domain)
        self.assertEqual(redirect_resp.get('Location'),
                         'http://www.go_to_google.com/and/authenticate/and/come/back')
        self.assertEqual(redirect_resp.status_code, 302)
        user.delete()

    @patch.object(oauth2client.django_orm.Storage, 'get')
    @patch(settings.GAPPS_LOGIN_SUCCESS_HANDLER)
    def test_login_begin_has_credential_different_domain(self, login_handler,
                                                         mock_get):
        login_handler.return_value = HttpResponseRedirect('/somewhere')

        user = User(first_name='vivek', last_name='chand',
                    username='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423', 'hd': 'rajnikanth.com'},
            'and_some_more': 'blah_blah_blah'}

        class credential(object):
            token_response = oauth2_response
            invalid = False

        mock_get.return_value = credential()
        request = HttpRequest()
        request.META = {
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'REMOTE_ADDR': '6457.255.345.123',
        }
        request.GET = {
            'domain': 'vivekchand.info'
        }
        request.user = user
        redirect_response = login_begin(request)

        self.assertEqual(redirect_response.status_code, 302)
        self.assertTrue('https://accounts.google.com/o/oauth2/auth?state=' in
                        redirect_response.get('Location'))
        self.assertTrue('hd=vivekchand.info' in
                        redirect_response.get('Location'))

        user.delete()

    @patch.object(CredentialsModel.objects, 'get')
    def test_get_access_token(self, mock_cred_obj_get):
        user = User(first_name='vivek', last_name='chand',
                    email='vivek@rajnikanth.com')
        user.save()

        oauth2_response = {
            'access_token': '5435rwesdfsd!!qw4324321eqw23@!@###asdasd',
            'id_token': {'id': '42342423432423', 'hd': 'rajnikanth.com'},
            'and_some_more': 'blah_blah_blah'}

        class oauth2client_credential(object):
            class credential(object):
                token_response = oauth2_response
                invalid = False

        mock_cred_obj_get.return_value = oauth2client_credential()

        access_token = get_access_token(user)
        self.assertEqual(access_token, oauth2_response.get('access_token'))

        user.delete()

    @patch.object(utils, 'get_access_token')
    @patch.object(utils, 'do_request')
    def test_authorized_request(self, mock_do_request, mock_get_access_token):
        user = User(first_name='vivek', last_name='chand',
                    email='vivek@rajnikanth.com')
        user.save()
        mock_do_request.return_value = 'god'
        mock_get_access_token.return_value = '5435rwesdfsd!!qw4324321eqw23@!@###asdasd'
        url = 'http://googleapis.com/search/?whoami'
        response = authorized_request(user, url)
        self.assertEqual(response, 'god')
        user.delete()


    def test_utils_get_organization_name(self):
        response = ({'status': '200', 'gdata-version': '1.0',
                     'x-xss-protection': '1; mode=block',
                     'content-location': ('https://apps-apis.google.com/a/feeds/domain/2.0/aplopio.com'
                                          '/general/organizationName?key=19785738660-v1tikhnpih8c6jb7f2'
                                          'arp5lp03b0m756.apps.googleusercontent.com'),
                     'x-content-type-options': 'nosniff',
                     'alternate-protocol': '443:quic',
                     'transfer-encoding': 'chunked',
                     'expires': 'Wed, 02 Apr 2014 06:41:59 GMT',
                     'vary': 'Accept, X-GData-Authorization, GData-Version',
                     'server': 'GSE', 'last-modified': 'Wed, 02 Apr 2014 06:41:59 GMT',
                     'cache-control': 'private, max-age=0, must-revalidate, no-transform',
                     'date': 'Wed, 02 Apr 2014 06:41:59 GMT',
                     'x-frame-options': 'SAMEORIGIN',
                     'content-type': 'application/atom+xml; charset=UTF-8'},
                    ("<?xml version='1.0' encoding='UTF-8'?><entry xmlns='http://www.w3.org/2005/Atom'"
                     " xmlns:apps='http://schemas.google.com/apps/2006'><id>https://apps-apis.google.com"
                     "/a/feeds/domain/2.0/aplopio.com/general/organizationName</id><updated>2014-04-02T06"
                     ":41:59.611Z</updated><link rel='self' type='application/atom+xml' "
                     "href='https://apps-apis.google.com/a/feeds/domain/2.0/aplopio.com/general/organizationName"
                     "'/><link rel='edit' type='application/atom+xml' href='https://apps-apis.google.com/a/feeds/"
                     "domain/2.0/aplopio.com/general/organizationName'/><apps:property name='organizationName' "
                     "value='Aplopio Technology Private Limited'/></entry>"))

        organization_name = _get_organization_name(response)
        self.assertEqual(organization_name, 'Aplopio Technology Private Limited')

    @patch.object(utils, 'authorized_request')
    @patch.object(utils, '_get_organization_name')
    def test_get_organization_name(self, mock_utils_get_organization_name,
                                   mock_authorized_request):
        admin_user = User(first_name='vivek', last_name='chand',
                          email='vivek@rajnikanth.com')
        admin_user.save()
        mock_authorized_request = {'organization_name': 'Aplopio Technology Private Limited'}
        mock_utils_get_organization_name.return_value = 'Aplopio Technology Private Limited'
        organization_name = get_organization_name(admin_user, 'aplopio.com')
        admin_user.delete()

    @patch.object(json, 'loads')
    @patch.object(requests, 'get')
    def test_get_profile_valid(self, mock_request_get, json_loads):

        get_return_value = MagicMock(
            content='{"valid_property_name": "valid_property_value"}',
            status_code=200
        )
        mock_request_get.return_value = get_return_value

        return_value = {
            'valid_property_name': 'valid_property_value'
        }

        json_loads.return_value = return_value

        details = utils.get_profile("some url")
        assert details == return_value
