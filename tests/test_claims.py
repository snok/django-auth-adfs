from django.core.exceptions import PermissionDenied
from django.contrib.auth.models import User, Group
from django.test import TestCase
from httmock import with_httmock, urlmatch
from .utils import get_base_claims, encode_jwt
from django_auth_adfs.backend import AdfsBackend


@urlmatch(path=r"^/adfs/oauth2/token$")
def token_response(url, request):
    claims = get_base_claims()
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def expired_token_response(url, request):
    claims = get_base_claims()
    claims["iat"] -= 10000
    claims["exp"] -= 10000
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def corrupt_token_response(url, request):
    return {'status_code': 200, 'content': b'{"access_token":"invalid_token"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def invalid_token_response(url, request):
    claims = get_base_claims()
    claims.pop("iss")
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def single_group_token_response(url, request):
    claims = get_base_claims()
    claims["group"] = "group1"
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def is_staff_token_response(url, request):
    claims = get_base_claims()
    claims["user_is_superuser"] = "x"
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


class ClaimTests(TestCase):
    def setUp(self):
        Group.objects.create(name='group1')
        Group.objects.create(name='group2')
        Group.objects.create(name='group3')

    @with_httmock(corrupt_token_response)
    def test_corrupt_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(expired_token_response)
    def test_expired_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(invalid_token_response)
    def test_invalid_token(self):
        backend = AdfsBackend()
        self.assertRaises(PermissionDenied, backend.authenticate, authorization_code='testcode')

    @with_httmock(single_group_token_response)
    def test_single_group_token(self):
        backend = AdfsBackend()
        user = backend.authenticate(authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(len(user.groups.all()), 1)
        self.assertEqual(user.groups.all()[0].name, "group1")

    @with_httmock(token_response)
    def test_bool_claim(self):
        backend = AdfsBackend()
        user = backend.authenticate(authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(user.is_staff, True)
        self.assertEqual(user.is_superuser, True)

    @with_httmock(is_staff_token_response)
    def test_is_staff_bool_claim(self):
        backend = AdfsBackend()
        user = backend.authenticate(authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(user.is_staff, True)
        self.assertEqual(user.is_superuser, False)
