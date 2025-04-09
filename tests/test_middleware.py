from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponseRedirect
from django.test import RequestFactory, TestCase
from django_auth_adfs.middleware import LoginRequiredMiddleware


class LoginRequiredMiddlewareTestCase(TestCase):
    def setUp(self):
        self.rf = RequestFactory()
        self.middleware = LoginRequiredMiddleware(get_response=lambda *args: None)

    def test_not_exempt_redirects(self):
        request = self.rf.get('/page/')
        request.user = AnonymousUser()
        response = self.middleware(request)
        assert isinstance(response, HttpResponseRedirect)

        request = self.rf.get('/nested/redirect/')
        request.user = AnonymousUser()
        response = self.middleware(request)
        assert isinstance(response, HttpResponseRedirect)

    def test_exempt(self):
        request = self.rf.get('/api')
        request.user = AnonymousUser()
        response = self.middleware(request)
        assert response is None

        request = self.rf.get('/nested/path/')
        request.user = AnonymousUser()
        response = self.middleware(request)
        assert response is None

        request = self.rf.get('/nested/path/further')
        request.user = AnonymousUser()
        response = self.middleware(request)
        assert response is None
