from django.test import TestCase, Client
from httmock import with_httmock, urlmatch
from .utils import get_base_claims, encode_jwt
from django.contrib.auth.models import User, Group

client = Client()


@urlmatch(path=r"^/adfs/oauth2/token$")
def token_response(url, request):
    claims = get_base_claims()
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


@urlmatch(path=r"^/adfs/oauth2/token$")
def inactive_user_token_response(url, request):
    claims = get_base_claims()
    claims["winaccountname"] = "locked_user"
    token = encode_jwt(claims)
    return {'status_code': 200, 'content': b'{"access_token":"' + token + b'"}'}


class ClientRequestTests(TestCase):
    def setUp(self):
        Group.objects.create(name='group1')
        Group.objects.create(name='group2')
        Group.objects.create(name='group3')
        User.objects.create(**{
            User.USERNAME_FIELD: "locked_user",
            "is_active": False
        })

    @with_httmock(token_response)
    def test_authentication(self):
        response = client.get("/oauth2/login", {'code': 'testcode'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith('/accounts/profile/'))

    @with_httmock(token_response)
    def test_authentication_with_next_field(self):
        response = client.get("/oauth2/login", {'code': 'testcode', 'next': '/other/url'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response['Location'].endswith('/other/url'))

    @with_httmock(token_response)
    def test_empty_authentication(self):
        response = client.get("/oauth2/login", {'code': ''})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Login failed")

    @with_httmock(token_response)
    def test_missing_code(self):
        response = client.get("/oauth2/login")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.content, b"Login failed")

    @with_httmock(inactive_user_token_response)
    def test_inactive_user(self):
        response = client.get("/oauth2/login", {'code': 'testcode'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content, b"Account disabled")

    @with_httmock(token_response)
    def test_login_redir(self):
        response = client.get("/test/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], 'https://adfs.example.com/adfs/oauth2/authorize?response_type=code&'
                                               'client_id=your-configured-client-id&resource=your-adfs-RPT-name&'
                                               'redirect_uri=example.com')

    @with_httmock(token_response)
    def test_context_processor(self):
        response = client.get("/context_processor/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'https://adfs.example.com/adfs/oauth2/authorize?response_type=code&amp;'
                                           b'client_id=your-configured-client-id&amp;resource=your-adfs-RPT-name&amp;'
                                           b'redirect_uri=example.com\n')
