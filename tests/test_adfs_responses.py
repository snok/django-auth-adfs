from django.core.exceptions import PermissionDenied
from django.test import TestCase
from httmock import with_httmock, urlmatch
from django_auth_adfs.backend import AdfsBackend


@urlmatch(path=r"^/adfs/oauth2/token$")
def response_400(url, request):
    return {'status_code': 400, 'content': b'{"error_description":"something went wrong"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def response_500(url, request):
    return {'status_code': 500, 'content': b'Internal Server Error'}


class ADFSRespsoseTests(TestCase):
    @with_httmock(response_400)
    def test_expired_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(response_500)
    def test_corrupt_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')
