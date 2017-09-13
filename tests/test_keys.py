import os
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, Client
from httmock import with_httmock, urlmatch
from mock import patch, mock_open

from django_auth_adfs.backend import AdfsBackend
from .utils import get_base_claims, encode_jwt

client = Client()


@urlmatch(path=r"^/adfs/oauth2/token$")
def token_response(url, request):
    claims = get_base_claims()
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/FederationMetadata/2007-06/FederationMetadata.xml$")
def metadata_response(url, request):
    with open(os.path.join(os.path.dirname(__file__), "FederationMetadata_valid_cert_first.xml")) as f:
        return {'status_code': 200, 'content': f.read()}


@urlmatch(path=r"^/FederationMetadata/2007-06/FederationMetadata.xml$")
def empty_metadata_response(url, request):
    with open(os.path.join(os.path.dirname(__file__), "FederationMetadata_empty.xml")) as f:
        return {'status_code': 200, 'content': f.read()}


@urlmatch(path=r"^/FederationMetadata/2007-06/FederationMetadata.xml$")
def metadata_response_2(url, request):
    with open(os.path.join(os.path.dirname(__file__), "FederationMetadata_valid_cert_second.xml")) as f:
        return {'status_code': 200, 'content': f.read()}


class KeysTests(TestCase):
    @with_httmock(token_response)
    def test_invalid_certificate_path(self):
        mock_file_path = "/path/to/cert.pem"
        with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", mock_file_path):
                with patch("django_auth_adfs.backend.isfile") as mock_isfile:
                    mock_isfile.return_value = False
                    self.assertRaises(ImproperlyConfigured, AdfsBackend)

    @with_httmock(token_response)
    def test_invalid_certificate(self):
        with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", None):
                self.assertRaises(ImproperlyConfigured, AdfsBackend)

    @with_httmock(token_response)
    def test_signing_cert_file(self):
        cert_content = settings.AUTH_ADFS["SIGNING_CERT"]
        mock_file_path = "/path/to/cert.pem"
        with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", mock_file_path):
                with patch("django_auth_adfs.backend.isfile") as mock_isfile:
                    mock_isfile.return_value = True
                    with patch("django_auth_adfs.backend.open", mock_open(read_data=cert_content)) as mock_file:
                        AdfsBackend()
                        mock_file.assert_called_once_with(mock_file_path, 'r')

    @with_httmock(token_response, metadata_response)
    def test_auto_certificate_loading(self):
        cert_exp_time = datetime.now() - timedelta(hours=25)
        with patch("django_auth_adfs.backend.AdfsBackend._key_age", cert_exp_time):
            with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
                with patch("django_auth_adfs.backend.settings.SIGNING_CERT", True):
                    backend = AdfsBackend()
                    user = backend.authenticate(authorization_code="dummycode")
                    self.assertIsInstance(user, User)

    @with_httmock(token_response, metadata_response_2)
    def test_auto_certificate_loading_2(self):
        cert_exp_time = datetime.now() - timedelta(hours=25)
        with patch("django_auth_adfs.backend.AdfsBackend._key_age", cert_exp_time):
            with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
                with patch("django_auth_adfs.backend.settings.SIGNING_CERT", True):
                    backend = AdfsBackend()
                    user = backend.authenticate(authorization_code="dummycode")
                    self.assertIsInstance(user, User)

    @with_httmock(token_response, empty_metadata_response)
    def test_keep_keys_on_failure(self):
        cert_exp_time = datetime.now() - timedelta(hours=25)
        with patch("django_auth_adfs.backend.AdfsBackend._key_age", cert_exp_time):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", True):
                backend = AdfsBackend()
                user = backend.authenticate(authorization_code="dummycode")
                self.assertIsInstance(user, User)

    @with_httmock(token_response, empty_metadata_response)
    def test_empty_auto_certificate_loading(self):
        with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", True):
                self.assertRaises(Exception, AdfsBackend)
