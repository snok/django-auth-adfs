from django.contrib.auth import authenticate, login
from django.http.response import HttpResponse
from django.shortcuts import redirect
from django.views.generic import View

from django_auth_adfs.config import Settings
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
                settings = Settings()
                # Redirect to a success page.
                return redirect(settings.ADFS_AFTER_LOGIN_URL)
            else:
                # Return a 'disabled account' error message
                return HttpResponse("Login failed")
        else:
            # Return an 'invalid login' error message.
            return HttpResponse("Login failed")


class LoginView(View):
    def get(self, request):
        """
        Redirects the user to ADFS for logig.

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(get_adfs_auth_url(request))
