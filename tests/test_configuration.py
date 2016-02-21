from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, Client
from httmock import with_httmock, urlmatch
from .utils import get_base_claims, encode_jwt
from mock import patch, mock_open
from django_auth_adfs.backend import AdfsBackend
from django_auth_adfs.config import settings as adfs_settings
from django.conf import settings

client = Client()


@urlmatch(path=r"^/adfs/oauth2/token$")
def token_response(url, request):
    claims = get_base_claims()
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"'+token+b'"}'}


class InvalidConfigurationTests(TestCase):
    @with_httmock(token_response)
    def test_invalid_redir_uri(self):
        backend = AdfsBackend()
        with patch("django_auth_adfs.backend.settings.ADFS_REDIR_URI", None):
            self.assertRaises(ImproperlyConfigured, backend.authenticate, authorization_code='testcode')

    @with_httmock(token_response)
    def test_invalid_setting(self):
        self.assertRaises(AttributeError, adfs_settings.__getattr__, "NON_EXISTING")

    @with_httmock(token_response)
    def test_invalid_certificate(self):
        with patch("django_auth_adfs.backend.settings.ADFS_SIGNING_CERT", None):
            self.assertRaises(ImproperlyConfigured, AdfsBackend)

    @with_httmock(token_response)
    def test_invalid_certificate_path(self):
        cert_content = settings.AUTH_ADFS["ADFS_SIGNING_CERT"]
        mock_file_path = "/path/to/cert.pem"
        with patch("django_auth_adfs.backend.settings.ADFS_SIGNING_CERT", mock_file_path):
            with patch("django_auth_adfs.backend.isfile") as mock_isfile:
                mock_isfile.return_value = False
                self.assertRaises(ImproperlyConfigured, AdfsBackend)

    @with_httmock(token_response)
    def test_claim_mapping_non_existing_model_field(self):
        backend = AdfsBackend()
        mock_claim_mapping = {
            "nonexisting": "given_name",
            "last_name": "family_name",
            "email": "email"
        }
        with patch("django_auth_adfs.backend.settings.ADFS_CLAIM_MAPPING", mock_claim_mapping):
            self.assertRaises(ImproperlyConfigured, backend.authenticate, authorization_code="dummycode")

    @with_httmock(token_response)
    def test_claim_mapping_non_existing_claim(self):
        backend = AdfsBackend()
        mock_claim_mapping = {
            "first_name": "nonexisting",
            "last_name": "family_name",
            "email": "email"
        }
        with patch("django_auth_adfs.backend.settings.ADFS_CLAIM_MAPPING", mock_claim_mapping):
            self.assertRaises(KeyError, backend.authenticate, authorization_code="dummycode")

    @with_httmock(token_response)
    def test_group_claim(self):
        backend = AdfsBackend()
        with patch("django_auth_adfs.backend.settings.ADFS_GROUP_CLAIM", "nonexisting"):
            self.assertRaises(ImproperlyConfigured, backend.authenticate, authorization_code="dummycode")


class ConfigurationVariationsTests(TestCase):
    @with_httmock(token_response)
    def test_invalid_redir_uri(self):
        backend = AdfsBackend()
        with patch("django_auth_adfs.backend.settings.ADFS_REDIR_URI", None):
            self.assertRaises(ImproperlyConfigured, backend.authenticate, authorization_code='testcode')

    @with_httmock(token_response)
    def test_invalid_certificate(self):
        with patch("django_auth_adfs.backend.settings.ADFS_SIGNING_CERT", None):
            self.assertRaises(ImproperlyConfigured, AdfsBackend)

    @with_httmock(token_response)
    def test_claim_mapping_non_existing_model_field(self):
        backend = AdfsBackend()
        mock_claim_mapping = {
            "nonexisting": "given_name",
            "last_name": "family_name",
            "email": "email"
        }
        with patch("django_auth_adfs.backend.settings.ADFS_CLAIM_MAPPING", mock_claim_mapping):
            self.assertRaises(ImproperlyConfigured, backend.authenticate, authorization_code="dummycode")

    @with_httmock(token_response)
    def test_claim_mapping_non_existing_claim(self):
        backend = AdfsBackend()
        mock_claim_mapping = {
            "first_name": "nonexisting",
            "last_name": "family_name",
            "email": "email"
        }
        with patch("django_auth_adfs.backend.settings.ADFS_CLAIM_MAPPING", mock_claim_mapping):
            self.assertRaises(KeyError, backend.authenticate, authorization_code="dummycode")

    @with_httmock(token_response)
    def test_signing_cert_file(self):
        cert_content = settings.AUTH_ADFS["ADFS_SIGNING_CERT"]
        mock_file_path = "/path/to/cert.pem"
        with patch("django_auth_adfs.backend.settings.ADFS_SIGNING_CERT", mock_file_path):
            with patch("django_auth_adfs.backend.isfile") as mock_isfile:
                mock_isfile.return_value = True
                with patch("django_auth_adfs.backend.open", mock_open(read_data=cert_content)) as mock_file:
                    backend = AdfsBackend()
                    mock_file.assert_called_once_with(mock_file_path, 'r')

    @with_httmock(token_response)
    def test_authentication(self):
        with patch("django_auth_adfs.backend.settings.ADFS_LOGIN_REDIRECT_URL", "/test/path/"):
            response = client.get("/oauth2/login", {'code': 'testcode'})
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response['Location'].endswith('/test/path/'))
