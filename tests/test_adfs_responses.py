from django.core.exceptions import PermissionDenied
from django.test import TestCase
from httmock import with_httmock, urlmatch
from mock import patch
from django_auth_adfs.backend import AdfsBackend
from requests import HTTPError


@urlmatch(path=r"^/adfs/oauth2/token$")
def response_400(url, request):
    return {'status_code': 400, 'content': b'{"error_description":"something went wrong"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def response_500(url, request):
    return {'status_code': 500, 'content': b'Internal Server Error'}


@urlmatch(path=r"^/FederationMetadata/2007-06/FederationMetadata.xml$")
def metadata_response_404(url, request):
    return {'status_code': 404, 'content': b'{"File not found"}'}


class ADFSRespsoseTests(TestCase):
    @with_httmock(response_400)
    def test_expired_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(response_500)
    def test_corrupt_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(metadata_response_404)
    def test_missing_metadata(self):
        with patch("django_auth_adfs.backend.AdfsBackend._public_keys", []):
            with patch("django_auth_adfs.backend.settings.SIGNING_CERT", True):
                self.assertRaises(HTTPError, AdfsBackend)
