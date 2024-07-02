"""
Based on https://djangosnippets.org/snippets/1179/
"""
import logging
from datetime import datetime
from re import compile

from django.conf import settings as django_settings
from django.contrib import auth
from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.urls import reverse
from requests import HTTPError

from django_auth_adfs.backend import AdfsAuthCodeBackend
from django_auth_adfs.exceptions import MFARequired
from django_auth_adfs.config import settings

LOGIN_EXEMPT_URLS = [
    compile(django_settings.LOGIN_URL.lstrip('/')),
    compile(reverse("django_auth_adfs:login").lstrip('/')),
    compile(reverse("django_auth_adfs:logout").lstrip('/')),
    compile(reverse("django_auth_adfs:callback").lstrip('/')),
]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    LOGIN_EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]

logger = logging.getLogger("django_auth_adfs")


class LoginRequiredMiddleware:
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        assert hasattr(request, 'user'), "The Login Required middleware requires " \
                                         "authentication middleware to be installed. " \
                                         "Edit your MIDDLEWARE setting to insert " \
                                         "'django.contrib.auth.middleware.AuthenticationMiddleware'. " \
                                         "If that doesn't work, ensure your TEMPLATE_CONTEXT_PROCESSORS " \
                                         "setting includes 'django.core.context_processors.auth'."
        if not request.user.is_authenticated:
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in LOGIN_EXEMPT_URLS):
                try:
                    return redirect_to_login(request.get_full_path())
                except MFARequired:
                    return redirect_to_login('django_auth_adfs:login-force-mfa')

        return self.get_response(request)


def adfs_refresh_middleware(get_response):
    def middleware(request):
        try:
            backend_str = request.session[auth.BACKEND_SESSION_KEY]
        except KeyError:
            pass
        else:
            backend = auth.load_backend(backend_str)
            if isinstance(backend, AdfsAuthCodeBackend):
                now = datetime.now() + settings.REFRESH_THRESHOLD
                expiry = datetime.fromisoformat(request.session['_adfs_token_expiry'])
                if now > expiry:
                    try:
                        backend.refresh_access_token(request, request.session['_adfs_refresh_token'])
                    except (PermissionDenied, HTTPError) as error:
                        logger.debug("Error refreshing access token: %s", error)
                        logout(request)
        return get_response(request)
    return middleware
