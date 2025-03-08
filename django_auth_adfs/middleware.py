"""
Based on https://djangosnippets.org/snippets/1179/
"""

import datetime
import logging
from re import compile

from django.conf import settings as django_settings
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse

from django_auth_adfs.exceptions import MFARequired
from django_auth_adfs.config import settings, provider_config
from django_auth_adfs.signals import post_authenticate
from django_auth_adfs.utils import _encrypt_token

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
    Middleware that handles the complete lifecycle of ADFS access and refresh tokens.

    This middleware will:
    1. Store tokens in the session after successful authentication
    2. Check if the access token is about to expire
    3. Use the refresh token to get a new access token if needed
    4. Update the tokens in the session
    5. Handle OBO (On-Behalf-Of) tokens for Microsoft Graph API

    To enable this middleware, add it to your MIDDLEWARE setting:
    'django_auth_adfs.middleware.TokenLifecycleMiddleware'

    You can configure the token refresh behavior with these settings:

    TOKEN_REFRESH_THRESHOLD: Number of seconds before expiration to refresh (default: 300)
    STORE_OBO_TOKEN: Boolean to enable/disable OBO token storage (default: True)
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Default settings
        self.threshold = getattr(settings, "TOKEN_REFRESH_THRESHOLD", 300)
        self.using_signed_cookies = (
            django_settings.SESSION_ENGINE
            == "django.contrib.sessions.backends.signed_cookies"
        )
        self.disable_for_signed_cookies = True
        self.store_obo_token = getattr(settings, "STORE_OBO_TOKEN", True)
        if self.using_signed_cookies:
            logger.warning(
                "TokenLifecycleMiddleware is enabled but you are using the signed_cookies session backend. "
                "Storing tokens in signed cookies is not recommended for security reasons and cookie size limitations. "
                "The middleware will not store tokens in the session. "
                "Consider using database or cache-based sessions instead."
            )

        # Connect the signal receiver
        post_authenticate.connect(self._capture_tokens_from_auth)

    def __call__(self, request):
        if hasattr(request, "user"):
            # Store tokens if they're available on the user object but not in the session
            self._store_tokens_from_user(request)
            if request.user.is_authenticated:
                self._handle_token_refresh(request)
        response = self.get_response(request)

        # This handles the case where authentication happens during the request
        if hasattr(request, "user"):
            self._store_tokens_from_user(request)

        return response

    def _store_tokens_from_user(self, request):
        """
        Store tokens from the user object in the session if they exist
        """
        if self.using_signed_cookies:
            return

        if not hasattr(request, "user") or not request.user.is_authenticated:
            return

        user = request.user
        session_modified = False

        # Check if user has tokens that aren't in the session
        if hasattr(user, "access_token") and user.access_token:
            encrypted_token = _encrypt_token(user.access_token)
            if encrypted_token and (
                not request.session.get("ADFS_ACCESS_TOKEN")
                or request.session.get("ADFS_ACCESS_TOKEN") != encrypted_token
            ):
                request.session["ADFS_ACCESS_TOKEN"] = encrypted_token
                session_modified = True

        if hasattr(user, "refresh_token") and user.refresh_token:
            encrypted_token = _encrypt_token(user.refresh_token)
            if encrypted_token and (
                not request.session.get("ADFS_REFRESH_TOKEN")
                or request.session.get("ADFS_REFRESH_TOKEN") != encrypted_token
            ):
                request.session["ADFS_REFRESH_TOKEN"] = encrypted_token
                session_modified = True

        if hasattr(user, "token_expires_at") and user.token_expires_at:
            expires_at_str = user.token_expires_at.isoformat()
            if (
                not request.session.get("ADFS_TOKEN_EXPIRES_AT")
                or request.session.get("ADFS_TOKEN_EXPIRES_AT") != expires_at_str
            ):
                request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at_str
                session_modified = True

        # Store OBO token if available and enabled
        if (
            self.store_obo_token
            and hasattr(user, "obo_access_token")
            and user.obo_access_token
        ):
            encrypted_token = _encrypt_token(user.obo_access_token)
            if encrypted_token and (
                not request.session.get("ADFS_OBO_ACCESS_TOKEN")
                or request.session.get("ADFS_OBO_ACCESS_TOKEN") != encrypted_token
            ):
                request.session["ADFS_OBO_ACCESS_TOKEN"] = encrypted_token
                session_modified = True

        # Store OBO token expiration if available
        if (
            self.store_obo_token
            and hasattr(user, "obo_token_expires_at")
            and user.obo_token_expires_at
        ):
            obo_expires_at_str = user.obo_token_expires_at.isoformat()
            if (
                not request.session.get("ADFS_OBO_TOKEN_EXPIRES_AT")
                or request.session.get("ADFS_OBO_TOKEN_EXPIRES_AT")
                != obo_expires_at_str
            ):
                request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = obo_expires_at_str
                session_modified = True

        if session_modified:
            request.session.modified = True
            logger.debug("Stored tokens from user object in session")

    def _handle_token_refresh(self, request):
        """
        Check if the access token needs to be refreshed and refresh it if needed
        """
        if self.using_signed_cookies:
            return

        if (
            "ADFS_ACCESS_TOKEN" not in request.session
            or "ADFS_REFRESH_TOKEN" not in request.session
            or "ADFS_TOKEN_EXPIRES_AT" not in request.session
        ):
            return

        try:
            expires_at = datetime.datetime.fromisoformat(
                request.session["ADFS_TOKEN_EXPIRES_AT"]
            )
            now = datetime.datetime.now()

            if (expires_at - now).total_seconds() <= self.threshold:
                logger.debug("Access token is about to expire, refreshing...")
                self._refresh_tokens(request)

            if (
                self.store_obo_token
                and "ADFS_OBO_ACCESS_TOKEN" in request.session
                and "ADFS_OBO_TOKEN_EXPIRES_AT" in request.session
            ):
                obo_expires_at = datetime.datetime.fromisoformat(
                    request.session["ADFS_OBO_TOKEN_EXPIRES_AT"]
                )
                if (obo_expires_at - now).total_seconds() <= self.threshold:
                    logger.debug("OBO token is about to expire, refreshing...")
                    self._refresh_obo_token(request)

        except Exception as e:
            logger.warning(f"Error checking token expiration: {e}")

    def _refresh_tokens(self, request):
        """
        Refresh the access token using the refresh token
        """
        if self.using_signed_cookies:
            return

        if "ADFS_REFRESH_TOKEN" not in request.session:
            return

        try:
            from django_auth_adfs.utils import _decrypt_token, _encrypt_token

            refresh_token = _decrypt_token(request.session["ADFS_REFRESH_TOKEN"])
            if not refresh_token:
                logger.warning("Failed to decrypt refresh token")
                return

            provider_config.load_config()

            data = {
                "grant_type": "refresh_token",
                "client_id": settings.CLIENT_ID,
                "refresh_token": refresh_token,
            }

            if settings.CLIENT_SECRET:
                data["client_secret"] = settings.CLIENT_SECRET

            response = provider_config.session.post(
                provider_config.token_endpoint, data=data, timeout=settings.TIMEOUT
            )
            if response.status_code == 200:
                token_data = response.json()
                request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token(
                    token_data["access_token"]
                )
                if "refresh_token" in token_data:
                    request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
                        token_data["refresh_token"]
                    )
                expires_in = int(
                    token_data.get("expires_in", 3600)
                )
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=expires_in
                )
                request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

                request.session.modified = True
                logger.debug("Successfully refreshed tokens")

                if self.store_obo_token:
                    self._refresh_obo_token(request)
            else:
                logger.warning(
                    f"Failed to refresh token: {response.status_code} {response.text}"
                )
                if settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE:
                    from django.contrib.auth import logout

                    logger.info("Logging out user due to token refresh failure")
                    logout(request)

        except Exception as e:
            logger.exception(f"Error refreshing tokens: {e}")
            if settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE:
                from django.contrib.auth import logout

                logger.info("Logging out user due to token refresh error")
                logout(request)

    def _refresh_obo_token(self, request):
        """
        Refresh the OBO token for Microsoft Graph API
        """
        if not self.store_obo_token:
            return

        if self.using_signed_cookies:
            return

        if "ADFS_ACCESS_TOKEN" not in request.session:
            return

        try:
            from django_auth_adfs.utils import _decrypt_token, _encrypt_token

            access_token = _decrypt_token(request.session["ADFS_ACCESS_TOKEN"])
            if not access_token:
                logger.warning("Failed to decrypt access token")
                return

            from django_auth_adfs.backend import AdfsBaseBackend

            backend = AdfsBaseBackend()
            obo_token = backend.get_obo_access_token(access_token)

            if obo_token:
                request.session["ADFS_OBO_ACCESS_TOKEN"] = _encrypt_token(obo_token)

                expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
                request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

                request.session.modified = True
                logger.debug("Successfully refreshed OBO token")
            else:
                logger.warning("Failed to get OBO token")

        except Exception as e:
            logger.exception(f"Error refreshing OBO token: {e}")

    def _capture_tokens_from_auth(
        self, sender, user, claims, adfs_response=None, **kwargs
    ):
        """
        Signal handler to capture tokens during authentication and store them on the user object.
        This ensures the tokens are available for the middleware to store in the session.
        """
        if not user:
            return

        if hasattr(sender, "access_token"):
            user.access_token = sender.access_token
        elif adfs_response and "access_token" in adfs_response:
            user.access_token = adfs_response["access_token"]

        if adfs_response and "refresh_token" in adfs_response:
            user.refresh_token = adfs_response["refresh_token"]

        if adfs_response and "expires_in" in adfs_response:
            user.token_expires_at = datetime.datetime.now() + datetime.timedelta(
                seconds=int(adfs_response["expires_in"])
            )

        if self.store_obo_token and hasattr(user, "access_token") and user.access_token:
            try:
                obo_token = sender.get_obo_access_token(user.access_token)
                if obo_token:
                    user.obo_access_token = obo_token
                    user.obo_token_expires_at = (
                        datetime.datetime.now() + datetime.timedelta(hours=1)
                    )
            except Exception as e:
                logger.warning(f"Error getting OBO token during authentication: {e}")
