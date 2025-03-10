"""
Tests for the TokenLifecycleMiddleware and TokenManager.
"""

import datetime
import json
import base64
from unittest.mock import Mock, patch
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.sessions.backends.db import SessionStore

from django_auth_adfs.middleware import TokenLifecycleMiddleware
from django_auth_adfs.config import settings as adfs_settings
from django_auth_adfs.token_manager import token_manager, TokenManager
from tests.settings import MIDDLEWARE

User = get_user_model()

MIDDLEWARE_WITH_TOKEN_LIFECYCLE = MIDDLEWARE + (
    "django_auth_adfs.middleware.TokenLifecycleMiddleware",
)


def create_test_token(claims=None, exp_delta=3600):
    """Create a test JWT token with the given claims and expiration delta."""
    if claims is None:
        claims = {}

    # Create a basic JWT token with ADFS-like structure
    header = {"typ": "JWT", "alg": "RS256", "x5t": "example-thumbprint"}

    # Add standard ADFS claims if not present
    now = int(time.time())
    if "iat" not in claims:
        claims["iat"] = now
    if "exp" not in claims:
        claims["exp"] = now + exp_delta
    if "aud" not in claims:
        claims["aud"] = "microsoft:identityserver:your-RelyingPartyTrust-identifier"
    if "iss" not in claims:
        claims["iss"] = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    if "sub" not in claims:
        claims["sub"] = "john.doe@example.com"

    # Encode each part
    header_part = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    claims_part = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    signature_part = base64.urlsafe_b64encode(b"test_signature").rstrip(b"=").decode()

    # Combine parts
    return f"{header_part}.{claims_part}.{signature_part}"


@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_TOKEN_LIFECYCLE)
class TokenLifecycleTests(TestCase):
    """
    Tests for the token lifecycle functionality, covering both TokenManager and TokenLifecycleMiddleware.
    """

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username="testuser")
        self.request = self.factory.get("/")
        self.request.user = self.user
        self.request.session = SessionStore()
        self.middleware = TokenLifecycleMiddleware(lambda r: None)

    def test_settings_configuration(self):
        """Test settings are properly loaded from Django settings"""
        with patch.object(adfs_settings, "TOKEN_REFRESH_THRESHOLD", 600), patch.object(
            adfs_settings, "STORE_OBO_TOKEN", False
        ), patch.object(adfs_settings, "LOGOUT_ON_TOKEN_REFRESH_FAILURE", True):

            manager = TokenManager()
            self.assertEqual(manager.refresh_threshold, 600)
            self.assertFalse(manager.store_obo_token)
            self.assertTrue(manager.logout_on_refresh_failure)

    def test_token_storage_capability(self):
        """Test token storage capability is properly added by middleware"""
        # Test with no session
        request_without_session = self.factory.get("/")
        self.middleware(request_without_session)
        self.assertFalse(hasattr(request_without_session, "token_storage"))

        # Test with signed cookies
        token_manager.using_signed_cookies = True
        try:
            self.middleware(self.request)
            self.assertFalse(hasattr(self.request, "token_storage"))
        finally:
            token_manager.using_signed_cookies = False

        # Test with valid session
        self.middleware(self.request)
        self.assertTrue(hasattr(self.request, "token_storage"))
        self.assertIs(self.request.token_storage, token_manager)

    def test_token_storage_and_retrieval(self):
        """Test the complete token storage and retrieval flow"""
        access_token = create_test_token({"type": "access"})
        refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability
        self.middleware(self.request)

        # Store tokens
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
            },
        )

        # Verify storage
        self.assertEqual(token_manager.get_access_token(self.request), access_token)
        self.assertTrue(token_manager.TOKEN_EXPIRES_AT_KEY in self.request.session)

        # Verify encryption
        encrypted = self.request.session[token_manager.ACCESS_TOKEN_KEY]
        self.assertNotEqual(encrypted, access_token)
        self.assertEqual(token_manager.decrypt_token(encrypted), access_token)

    def test_token_refresh_flow(self):
        """Test the complete token refresh flow"""
        old_access_token = create_test_token({"type": "access"}, exp_delta=60)
        old_refresh_token = create_test_token({"type": "refresh"})
        new_access_token = create_test_token({"type": "access"})
        new_refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability and setup expired token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            old_access_token,
            {
                "access_token": old_access_token,
                "refresh_token": old_refresh_token,
                "expires_in": 60,  # Will trigger refresh
            },
        )

        # Mock refresh response
        with patch("django_auth_adfs.token_manager.provider_config") as mock_config:
            mock_response = Mock(status_code=200)
            mock_response.json.return_value = {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "expires_in": 3600,
            }
            mock_config.session.post.return_value = mock_response
            mock_config.token_endpoint = "https://example.com/token"

            # Trigger refresh via middleware
            self.middleware(self.request)

            # Verify tokens were updated
            self.assertEqual(
                token_manager.get_access_token(self.request), new_access_token
            )

    def test_obo_token_management(self):
        """Test OBO token functionality when enabled"""
        access_token = create_test_token({"type": "access"})
        obo_token = create_test_token({"type": "obo"})

        # Add token storage capability and store regular token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {"access_token": access_token, "expires_in": 3600},
        )

        # Mock OBO flow
        with patch("django_auth_adfs.backend.AdfsBaseBackend") as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = obo_token

            # Verify OBO token storage and retrieval
            self.request.session[token_manager.OBO_ACCESS_TOKEN_KEY] = (
                token_manager.encrypt_token(obo_token)
            )
            self.request.session[token_manager.OBO_TOKEN_EXPIRES_AT_KEY] = (
                datetime.datetime.now() + datetime.timedelta(hours=1)
            ).isoformat()

            self.assertEqual(
                token_manager.get_obo_access_token(self.request), obo_token
            )

    def test_error_handling(self):
        """Test error handling in various scenarios"""
        # Add token storage capability
        self.middleware(self.request)

        # Test invalid data handling
        self.assertIsNone(token_manager.decrypt_token("invalid_data"))
        self.assertIsNone(token_manager.encrypt_token(None))

        # Test refresh failure
        access_token = create_test_token({"type": "access"}, exp_delta=-60)
        refresh_token = create_test_token({"type": "refresh"})

        with patch("django_auth_adfs.token_manager.provider_config") as mock_config:
            # Setup expired tokens first
            self.request.token_storage.store_tokens(
                self.request,
                access_token,
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": -60,  # Already expired
                },
            )

            mock_config.session.post.return_value = Mock(status_code=400, text="Error")
            mock_config.token_endpoint = "https://example.com/token"

            token_manager.logout_on_refresh_failure = True
            try:
                with patch("django_auth_adfs.token_manager.logout") as mock_logout:
                    token_manager.refresh_tokens(self.request)
                    mock_logout.assert_called_once_with(self.request)
            finally:
                token_manager.logout_on_refresh_failure = False

    def test_signed_cookies_handling(self):
        """Test behavior with signed cookies session backend"""
        token_manager.using_signed_cookies = True
        try:
            self.middleware(self.request)
            self.assertFalse(hasattr(self.request, "token_storage"))
        finally:
            token_manager.using_signed_cookies = False

    def test_middleware_integration(self):
        """Test TokenLifecycleMiddleware integration"""
        # Test with unauthenticated user
        self.request.user = AnonymousUser()
        response = self.middleware(self.request)
        self.assertIsNone(response)  # Middleware should pass through

        # Test with authenticated user
        self.request.user = self.user
        with patch.object(token_manager, "check_token_expiration") as mock_check:
            self.middleware(self.request)
            mock_check.assert_called_once_with(self.request)

    def test_clear_tokens(self):
        """Test clearing tokens from session"""
        access_token = create_test_token({"type": "access"})
        refresh_token = create_test_token({"type": "refresh"})

        # Add token storage capability and store tokens
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": 3600,
            },
        )

        # Verify tokens were stored
        self.assertTrue(token_manager.ACCESS_TOKEN_KEY in self.request.session)
        self.assertTrue(token_manager.REFRESH_TOKEN_KEY in self.request.session)

        # Clear tokens
        success = token_manager.clear_tokens(self.request)
        self.assertTrue(success)

        # Verify tokens were cleared
        self.assertFalse(token_manager.ACCESS_TOKEN_KEY in self.request.session)
        self.assertFalse(token_manager.REFRESH_TOKEN_KEY in self.request.session)
        self.assertFalse(token_manager.TOKEN_EXPIRES_AT_KEY in self.request.session)
        self.assertFalse(token_manager.OBO_ACCESS_TOKEN_KEY in self.request.session)
        self.assertFalse(token_manager.OBO_TOKEN_EXPIRES_AT_KEY in self.request.session)

    def test_refresh_obo_token_directly(self):
        """Test direct OBO token refresh"""
        access_token = create_test_token({"type": "access"})
        new_obo_token = create_test_token({"type": "obo"})

        # Add token storage capability and store access token
        self.middleware(self.request)
        self.request.token_storage.store_tokens(
            self.request,
            access_token,
            {"access_token": access_token, "expires_in": 3600},
        )

        # Mock OBO token acquisition and provider config
        with patch("django_auth_adfs.backend.AdfsBaseBackend") as mock_backend, patch(
            "django_auth_adfs.token_manager.provider_config"
        ) as mock_provider:

            mock_backend.return_value.get_obo_access_token.return_value = new_obo_token
            mock_provider.load_config.return_value = None
            mock_provider.token_endpoint = "https://example.com/token"
            mock_provider.session.verify = False  # Disable cert validation

            # Refresh OBO token
            success = token_manager.refresh_obo_token(self.request)
            self.assertTrue(success)

            # Verify new OBO token was stored
            obo_token = token_manager.get_obo_access_token(self.request)
            self.assertEqual(obo_token, new_obo_token)
            self.assertTrue(
                token_manager.OBO_TOKEN_EXPIRES_AT_KEY in self.request.session
            )
