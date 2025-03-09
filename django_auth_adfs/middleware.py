"""
Based on https://djangosnippets.org/snippets/1179/
"""

import logging
from re import compile

from django.conf import settings as django_settings
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse

from django_auth_adfs.exceptions import MFARequired
from django_auth_adfs.config import settings
from django_auth_adfs.token_manager import token_manager

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


class TokenLifecycleMiddleware:
    """
    Middleware that handles the lifecycle of ADFS access and refresh tokens.

    This middleware will:
    1. Check if the access token is about to expire
    2. Use the refresh token to get a new access token if needed
    3. Update the tokens in the session
    4. Handle OBO (On-Behalf-Of) tokens for Microsoft Graph API

    Token storage during authentication is handled by the backend when this middleware is enabled.

    To enable this middleware, add it to your MIDDLEWARE setting:
    'django_auth_adfs.middleware.TokenLifecycleMiddleware'

    You can configure the token refresh behavior with these settings:

    TOKEN_REFRESH_THRESHOLD: Number of seconds before expiration to refresh (default: 300)
    STORE_OBO_TOKEN: Boolean to enable/disable OBO token storage (default: True)
    LOGOUT_ON_TOKEN_REFRESH_FAILURE: Whether to log out the user if token refresh fails (default: False)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Log warning if using signed cookies
        if token_manager.using_signed_cookies:
            logger.warning(
                "TokenLifecycleMiddleware is enabled but you are using the signed_cookies session backend. "
                "Storing tokens in signed cookies is not recommended for security reasons and cookie size limitations. "
                "The middleware will not store tokens in the session. "
                "Consider using database or cache-based sessions instead."
            )

    def __call__(self, request):
        if hasattr(request, "user") and request.user.is_authenticated:
            # Check if tokens need to be refreshed
            token_manager.check_token_expiration(request)

        response = self.get_response(request)
        return response
