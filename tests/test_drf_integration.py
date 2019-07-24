import json
from copy import deepcopy

from django.conf import settings
from django.test import RequestFactory, TestCase, override_settings
from mock import patch
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from django_auth_adfs.config import ProviderConfig, Settings
from django_auth_adfs.rest_framework import (
    AdfsAccessTokenAuthentication,
)
from django_auth_adfs.rest_framework import views

from .utils import build_access_token_adfs, build_access_token_azure, mock_adfs


@override_settings(ROOT_URLCONF='tests.rest_urls')
class RestFrameworkIntegrationTests(TestCase):
    def setUp(self):
        self.drf_auth_class = AdfsAccessTokenAuthentication()

        adfs_response = build_access_token_adfs(RequestFactory().get('/'))[2]
        self.access_token_adfs = json.loads(adfs_response)['access_token']

        adfs_response = build_access_token_adfs(RequestFactory().get('/'))[2]
        self.refreshed_token_adfs = json.loads(adfs_response)['access_token']

        azure_response = build_access_token_azure(RequestFactory().get('/'))[2]
        self.access_token_azure = json.loads(azure_response)['access_token']

    @mock_adfs("2012")
    def test_access_token_2012(self):
        access_token_header = "Bearer {}".format(self.access_token_adfs)
        request = RequestFactory().get('/api', HTTP_AUTHORIZATION=access_token_header)

        user, token = self.drf_auth_class.authenticate(request)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(token, self.access_token_adfs.encode())

    @mock_adfs("2012")
    def test_access_callback_2012(self):
        request = APIRequestFactory().get('/api/oauth2/callback?code=%3Ccode%3E')

        response = views.OAuth2CallbackAPIView().dispatch(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['access_token'], self.access_token_adfs)
        self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("2012")
    def test_refresh_token_2012(self):
        access_token_header = "Bearer {}".format(self.access_token_adfs)
        request = APIRequestFactory().get(
            '/api/oauth2/refresh?token=%3Crefresh_token%3E',
            HTTP_AUTHORIZATION=access_token_header
        )

        response = views.OAuth2RefreshTokenAPIView().dispatch(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['access_token'], self.refreshed_token_adfs)
        self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("2016")
    def test_access_token_2016(self):
        access_token_header = "Bearer {}".format(self.access_token_adfs)
        request = RequestFactory().get('/api', HTTP_AUTHORIZATION=access_token_header)

        user, token = self.drf_auth_class.authenticate(request)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(token, self.access_token_adfs.encode())

    @mock_adfs("2016")
    def test_access_callback_2016(self):
        request = APIRequestFactory().get('/api/oauth2/callback?code=%3Ccode%3E')

        response = views.OAuth2CallbackAPIView().dispatch(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['access_token'], self.access_token_adfs)
        self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("2016")
    def test_refresh_token_2016(self):
        access_token_header = "Bearer {}".format(self.access_token_adfs)
        request = APIRequestFactory().get(
            '/api/oauth2/refresh?token=%3Crefresh_token%3E',
            HTTP_AUTHORIZATION=access_token_header
        )

        response = views.OAuth2RefreshTokenAPIView().dispatch(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['access_token'], self.refreshed_token_adfs)
        self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("azure")
    @override_settings()
    def test_access_token_azure(self):
        access_token_header = "Bearer {}".format(self.access_token_azure)
        request = RequestFactory().get('/api', HTTP_AUTHORIZATION=access_token_header)

        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_auth_adfs.config.settings", Settings()):
            provider_config = ProviderConfig()
            with patch("django_auth_adfs.adfs.provider_config", provider_config),\
                 patch("django_auth_adfs.backend.provider_config", provider_config):
                user, token = self.drf_auth_class.authenticate(request)
                self.assertEqual(user.username, "testuser")

    @mock_adfs("azure")
    @override_settings()
    def test_access_callback_azure(self):
        request = APIRequestFactory().get('/api/oauth2/callback?code=%3Ccode%3E')

        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_auth_adfs.config.settings", Settings()):
            provider_config = ProviderConfig()
            with patch("django_auth_adfs.adfs.provider_config", provider_config),\
                 patch("django_auth_adfs.backend.provider_config", provider_config):
                response = views.OAuth2CallbackAPIView().dispatch(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data['access_token'], self.access_token_azure)
                self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("azure")
    @override_settings()
    def test_refresh_token_azure(self):
        access_token_header = "Bearer {}".format(self.access_token_azure)
        request = APIRequestFactory().get(
            '/api/oauth2/refresh?token=%3Crefresh_token%3E',
            HTTP_AUTHORIZATION=access_token_header
        )

        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_auth_adfs.config.settings", Settings()):
            provider_config = ProviderConfig()
            with patch("django_auth_adfs.adfs.provider_config", provider_config),\
                 patch("django_auth_adfs.backend.provider_config", provider_config):
                response = views.OAuth2RefreshTokenAPIView().dispatch(request)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data['access_token'], self.access_token_azure)
                self.assertEqual(response.data['refresh_token'], 'random_refresh_token')

    @mock_adfs("2012")
    def test_access_token_exceptions(self):
        access_token_header = "Bearer non-existing-token"
        request = RequestFactory().get('/api', HTTP_AUTHORIZATION=access_token_header)

        with self.assertRaises(exceptions.AuthenticationFailed):
            self.drf_auth_class.authenticate(request)

        # use the azure token on adfs should not work
        access_token_header = "Bearer {}".format(self.access_token_azure)
        request = RequestFactory().get('/api', HTTP_AUTHORIZATION=access_token_header)

        with self.assertRaises(exceptions.AuthenticationFailed):
            self.drf_auth_class.authenticate(request)
