"""
Tests for the TokenLifecycleMiddleware and TokenManager.
"""

import datetime
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
        with patch.object(adfs_settings, 'TOKEN_REFRESH_THRESHOLD', 600), \
             patch.object(adfs_settings, 'STORE_OBO_TOKEN', False), \
             patch.object(adfs_settings, 'LOGOUT_ON_TOKEN_REFRESH_FAILURE', True):
            
            manager = TokenManager()
            self.assertEqual(manager.refresh_threshold, 600)
            self.assertFalse(manager.store_obo_token)
            self.assertTrue(manager.logout_on_refresh_failure)

    def test_token_storage_and_retrieval(self):
        """Test the complete token storage and retrieval flow"""
        # Store tokens
        token_manager.store_tokens(
            self.request,
            "test_access",
            {
                "access_token": "test_access",
                "refresh_token": "test_refresh",
                "expires_in": 3600
            }
        )

        # Verify storage
        self.assertEqual(token_manager.get_access_token(self.request), "test_access")
        self.assertTrue(token_manager.TOKEN_EXPIRES_AT_KEY in self.request.session)

        # Verify encryption
        encrypted = self.request.session[token_manager.ACCESS_TOKEN_KEY]
        self.assertNotEqual(encrypted, "test_access")
        self.assertEqual(token_manager.decrypt_token(encrypted), "test_access")

    def test_token_refresh_flow(self):
        """Test the complete token refresh flow"""
        # Setup expired token
        token_manager.store_tokens(
            self.request,
            "old_access",
            {
                "access_token": "old_access",
                "refresh_token": "old_refresh",
                "expires_in": 60  # Will trigger refresh
            }
        )

        # Mock refresh response
        with patch("django_auth_adfs.token_manager.provider_config") as mock_config:
            mock_response = Mock(status_code=200)
            mock_response.json.return_value = {
                "access_token": "new_access",
                "refresh_token": "new_refresh",
                "expires_in": 3600
            }
            mock_config.session.post.return_value = mock_response
            mock_config.token_endpoint = "https://example.com/token"

            # Trigger refresh via middleware
            self.middleware(self.request)

            # Verify tokens were updated
            self.assertEqual(
                token_manager.get_access_token(self.request),
                "new_access"
            )

    def test_obo_token_management(self):
        """Test OBO token functionality when enabled"""
        # Store regular token
        token_manager.store_tokens(
            self.request,
            "test_access",
            {"access_token": "test_access", "expires_in": 3600}
        )

        # Mock OBO flow
        with patch("django_auth_adfs.backend.AdfsBaseBackend") as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = "test_obo"
            
            # Verify OBO token storage and retrieval
            self.request.session[token_manager.OBO_ACCESS_TOKEN_KEY] = \
                token_manager.encrypt_token("test_obo")
            self.request.session[token_manager.OBO_TOKEN_EXPIRES_AT_KEY] = \
                (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()

            self.assertEqual(token_manager.get_obo_access_token(self.request), "test_obo")

    def test_error_handling(self):
        """Test error handling in various scenarios"""
        # Test invalid data handling
        self.assertIsNone(token_manager.decrypt_token("invalid_data"))
        self.assertIsNone(token_manager.encrypt_token(None))

        # Test refresh failure
        with patch("django_auth_adfs.token_manager.provider_config") as mock_config:
            # Setup expired tokens first
            token_manager.store_tokens(
                self.request,
                "old_access",
                {
                    "access_token": "old_access",
                    "refresh_token": "old_refresh",
                    "expires_in": -60  # Already expired
                }
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
            success = token_manager.store_tokens(
                self.request, "test_token", {"refresh_token": "test_refresh"}
            )
            self.assertFalse(success)
            self.assertFalse(token_manager.ACCESS_TOKEN_KEY in self.request.session)
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
