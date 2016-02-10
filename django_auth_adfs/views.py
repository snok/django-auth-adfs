from django.contrib.auth import authenticate, login
from django.http.response import HttpResponse
from django.shortcuts import redirect
from django.views.generic import View

from django_auth_adfs.config import settings
from .util import get_redir_uri, get_adfs_auth_url


class OAuth2View(View):
    def get(self, request):
        """
        Handles the redirect from ADFS to our site.
        We try to process the passed authorization code and login the user

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        code = request.GET["code"]

        redir_uri = get_redir_uri(request)
        user = authenticate(authorization_code=code, redir_uri=redir_uri)

        if user is not None:
            if user.is_active:
                login(request, user)
                # Redirect to the "after login" page.
                # Because we got redirected from ADFS, we can't know where the user came from
                # TODO: if ADFS_LOGIN_REDIRECT_URL is not set, use the django setting LOGIN_REDIRECT_URL
                return redirect(settings.ADFS_LOGIN_REDIRECT_URL)
            else:
                # Return a 'disabled account' error message
                return HttpResponse("Account disabled")
        else:
            # Return an 'invalid login' error message.
            return HttpResponse("Login failed")


class ADFSView(View):
    def get(self, request):
        """
        Redirects the user to ADFS for login.

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(get_adfs_auth_url(request))
