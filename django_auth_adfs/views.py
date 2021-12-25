import base64
import logging

from django.conf import settings as django_settings
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect
try:
    from django.utils.http import url_has_allowed_host_and_scheme
except ImportError:
    # Django <3.0
    from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme
from django.views.generic import View

from django_auth_adfs.config import provider_config, settings
from django_auth_adfs.exceptions import MFARequired

logger = logging.getLogger("django_auth_adfs")


class OAuth2CallbackView(View):
    def get(self, request):
        """
        Handles the redirect from ADFS to our site.
        We try to process the passed authorization code and login the user.

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        code = request.GET.get("code")
        if not code:
            # Return an error message
            return settings.CUSTOM_FAILED_RESPONSE_VIEW(
                request,
                error_message="No authorization code was provided.",
                status=400
            )

        redirect_to = request.GET.get("state")
        try:
            user = authenticate(request=request, authorization_code=code)
        except MFARequired:
            return redirect(provider_config.build_authorization_endpoint(request, force_mfa=True))

        if user:
            if user.is_active:
                login(request, user)
                # Redirect to the "after login" page.
                # Because we got redirected from ADFS, we can't know where the
                # user came from.
                if redirect_to:
                    redirect_to = base64.urlsafe_b64decode(redirect_to.encode()).decode()
                else:
                    redirect_to = django_settings.LOGIN_REDIRECT_URL
                url_is_safe = url_has_allowed_host_and_scheme(
                    url=redirect_to,
                    allowed_hosts=[request.get_host()],
                    require_https=request.is_secure(),
                )
                redirect_to = redirect_to if url_is_safe else '/'
                return redirect(redirect_to)
            else:
                # Return a 'disabled account' error message
                return settings.CUSTOM_FAILED_RESPONSE_VIEW(
                    request,
                    error_message="Your account is disabled.",
                    status=403
                )
        else:
            # Return an 'invalid login' error message
            return settings.CUSTOM_FAILED_RESPONSE_VIEW(
                request,
                error_message="Login failed.",
                status=401
            )


class OAuth2LoginView(View):
    def get(self, request):
        """
        Initiates the OAuth2 flow and redirect the user agent to ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(provider_config.build_authorization_endpoint(request))


class OAuth2LoginNoSSOView(View):
    def get(self, request):
        """
        Initiates the OAuth2 flow and redirect the user agent to ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(provider_config.build_authorization_endpoint(request, disable_sso=True))


class OAuth2LoginForceMFA(View):
    def get(self, request):
        """
        Initiates the OAuth2 flow and redirect the user agent to ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        return redirect(provider_config.build_authorization_endpoint(request, force_mfa=True))


class OAuth2LogoutView(View):
    def get(self, request):
        """
        Logs out the user from both Django and ADFS

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        logout(request)
        return redirect(provider_config.build_end_session_endpoint())
