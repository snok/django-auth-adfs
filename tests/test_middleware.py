import datetime
from unittest.mock import Mock, patch
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.sessions.backends.db import SessionStore

from django_auth_adfs.middleware import TokenLifecycleMiddleware
from django_auth_adfs.config import settings
from django_auth_adfs.utils import (
    get_access_token,
    get_obo_access_token,
    _encrypt_token,
    _decrypt_token,
)
from tests.settings import MIDDLEWARE

User = get_user_model()

# Add TokenLifecycleMiddleware to the existing middleware
MIDDLEWARE_WITH_TOKEN_LIFECYCLE = MIDDLEWARE + (
    "django_auth_adfs.middleware.TokenLifecycleMiddleware",
)


@override_settings(MIDDLEWARE=MIDDLEWARE_WITH_TOKEN_LIFECYCLE)
class TokenLifecycleMiddlewareTests(TestCase):
    """
    Tests for the TokenLifecycleMiddleware.

    The middleware handles the lifecycle of ADFS tokens:
    1. Storing tokens from user object to session
    2. Detecting when tokens need to be refreshed
    3. Refreshing tokens when needed
    4. Handling OBO (On-Behalf-Of) tokens
    """

    def setUp(self):
        """Set up test environment before each test"""
        self.factory = RequestFactory()
        self.middleware = TokenLifecycleMiddleware(lambda r: r)
        self.user = User.objects.create_user(username="testuser")
        self.request = self.factory.get("/")
        self.request.user = self.user
        self.request.session = SessionStore()

    # Group 1: Initialization Tests

    def test_init_with_default_settings(self):
        """Test middleware initialization with default settings"""
        middleware = TokenLifecycleMiddleware(lambda r: r)
        self.assertEqual(middleware.threshold, 300)
        self.assertTrue(middleware.store_obo_token)
        self.assertFalse(middleware.using_signed_cookies)

    def test_init_with_custom_settings(self):
        """Test middleware initialization with custom settings"""
        with patch("django_auth_adfs.middleware.getattr") as mock_getattr:
            # Mock getattr to return custom values
            mock_getattr.side_effect = lambda obj, name, default: {
                "TOKEN_REFRESH_THRESHOLD": 600,
                "STORE_OBO_TOKEN": False,
            }.get(name, default)

            middleware = TokenLifecycleMiddleware(lambda r: r)

            # Verify custom settings are applied
            self.assertEqual(middleware.threshold, 600)
            self.assertFalse(middleware.store_obo_token)

    # Group 2: Token Storage Tests

    def test_store_tokens_from_user(self):
        """Test storing tokens from user object to session"""
        # Set tokens on user object
        setattr(self.user, "access_token", "test_access_token")
        setattr(self.user, "refresh_token", "test_refresh_token")
        setattr(
            self.user,
            "token_expires_at",
            datetime.datetime.now() + datetime.timedelta(hours=1),
        )
        setattr(self.user, "obo_access_token", "test_obo_token")
        setattr(
            self.user,
            "obo_token_expires_at",
            datetime.datetime.now() + datetime.timedelta(hours=1),
        )

        # Call middleware
        self.middleware._store_tokens_from_user(self.request)

        # Check session - decrypt tokens before comparing
        self.assertEqual(
            _decrypt_token(self.request.session["ADFS_ACCESS_TOKEN"]),
            "test_access_token",
        )
        self.assertEqual(
            _decrypt_token(self.request.session["ADFS_REFRESH_TOKEN"]),
            "test_refresh_token",
        )
        self.assertEqual(
            _decrypt_token(self.request.session["ADFS_OBO_ACCESS_TOKEN"]),
            "test_obo_token",
        )
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)
        self.assertTrue("ADFS_OBO_TOKEN_EXPIRES_AT" in self.request.session)

    def test_store_partial_tokens_from_user(self):
        """Test storing partial token data (only access token without refresh token)"""
        # Set only access token on user object
        setattr(self.user, "access_token", "test_access_token")
        setattr(
            self.user,
            "token_expires_at",
            datetime.datetime.now() + datetime.timedelta(hours=1),
        )
        # No refresh token or OBO token

        # Call middleware
        self.middleware._store_tokens_from_user(self.request)

        # Check session - should have access token but not refresh token
        self.assertEqual(
            _decrypt_token(self.request.session["ADFS_ACCESS_TOKEN"]),
            "test_access_token",
        )
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in self.request.session)
        self.assertFalse("ADFS_REFRESH_TOKEN" in self.request.session)
        self.assertFalse("ADFS_OBO_ACCESS_TOKEN" in self.request.session)

    def test_store_tokens_from_user_with_signed_cookies(self):
        """Test that tokens are not stored when using signed cookies"""
        self.middleware.using_signed_cookies = True
        setattr(self.user, "access_token", "test_access_token")

        self.middleware._store_tokens_from_user(self.request)
        self.assertFalse("ADFS_ACCESS_TOKEN" in self.request.session)

    def test_session_modified_flag(self):
        """Test session.modified is set correctly during token storage operations"""
        # Test 1: When tokens are added, session.modified should be True
        self.request.session.modified = False
        setattr(self.user, "access_token", "new_token")
        self.middleware._store_tokens_from_user(self.request)
        # With encryption, session will always be modified when tokens are stored
        # so we can't test for False here anymore
        self.assertTrue(self.request.session.modified)

        # Test 2: Reset and test when no changes are made
        self.request.session.modified = False
        # Remove the token attribute so no changes will be made
        delattr(self.user, "access_token")
        self.middleware._store_tokens_from_user(self.request)
        self.assertFalse(self.request.session.modified)

    # Group 3: Token Refresh Detection Tests

    def test_handle_token_refresh_not_needed(self):
        """Test token refresh when it's not needed"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        expires_at = datetime.datetime.now() + datetime.timedelta(
            hours=1
        )  # 1 hour to expiry
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, "_refresh_tokens") as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_not_called()

    def test_handle_token_refresh_needed(self):
        """Test token refresh when it's needed"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        expires_at = datetime.datetime.now() + datetime.timedelta(
            seconds=60
        )  # 1 minute to expiry
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, "_refresh_tokens") as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_called_once_with(self.request)

    def test_handle_expired_token(self):
        """Test token refresh when token is already expired"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        expires_at = datetime.datetime.now() - datetime.timedelta(
            hours=1
        )  # Expired 1 hour ago
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        with patch.object(self.middleware, "_refresh_tokens") as mock_refresh:
            self.middleware._handle_token_refresh(self.request)
            mock_refresh.assert_called_once_with(self.request)

    def test_obo_token_expires_before_access_token(self):
        """Test when OBO token expires before access token"""
        # Set up access token with long expiry
        self.request.session["ADFS_ACCESS_TOKEN"] = "access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "refresh_token"
        access_token_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = (
            access_token_expires_at.isoformat()
        )

        # Set up OBO token with short expiry
        self.request.session["ADFS_OBO_ACCESS_TOKEN"] = "obo_token"
        obo_expires_at = datetime.datetime.now() + datetime.timedelta(seconds=30)
        self.request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = obo_expires_at.isoformat()

        # Should refresh only OBO token
        with patch.object(
            self.middleware, "_refresh_tokens"
        ) as mock_refresh_token, patch.object(
            self.middleware, "_refresh_obo_token"
        ) as mock_refresh_obo:
            self.middleware._handle_token_refresh(self.request)

            # Verify only OBO token is refreshed, not the access token
            mock_refresh_token.assert_not_called()
            mock_refresh_obo.assert_called_once_with(self.request)

            # Verify session state remains unchanged for access token
            self.assertEqual(self.request.session["ADFS_ACCESS_TOKEN"], "access_token")
            self.assertEqual(
                self.request.session["ADFS_REFRESH_TOKEN"], "refresh_token"
            )
            self.assertEqual(
                self.request.session["ADFS_TOKEN_EXPIRES_AT"],
                access_token_expires_at.isoformat(),
            )

    # Group 4: Token Refresh Implementation Tests

    @patch("django_auth_adfs.middleware.provider_config")
    def test_refresh_token_success(self, mock_provider_config):
        """Test successful token refresh"""
        # Set up mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
        }

        # Configure the mock
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = (
            "https://adfs.example.com/adfs/oauth2/token"
        )

        # Set up session with expired token
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("old_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token("old_refresh_token")
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now() - datetime.timedelta(minutes=5)
        ).isoformat()

        # Mock the OBO token refresh to prevent real HTTP requests
        with patch.object(self.middleware, "_refresh_obo_token") as mock_refresh_obo:
            # Call refresh method
            self.middleware._refresh_tokens(self.request)

            # Check that tokens were updated
            self.assertEqual(
                _decrypt_token(self.request.session["ADFS_ACCESS_TOKEN"]),
                "new_access_token",
            )
            self.assertEqual(
                _decrypt_token(self.request.session["ADFS_REFRESH_TOKEN"]),
                "new_refresh_token",
            )

    @patch("django_auth_adfs.middleware.provider_config")
    def test_refresh_token_without_new_refresh_token(self, mock_provider_config):
        """Test token refresh when response doesn't include a new refresh token"""
        # Set up mock response without refresh_token
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "expires_in": 3600,
        }

        # Configure the mock
        mock_provider_config.session.post.return_value = mock_response
        mock_provider_config.token_endpoint = (
            "https://adfs.example.com/adfs/oauth2/token"
        )

        # Set up session with expired token
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("old_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token("old_refresh_token")
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now() - datetime.timedelta(minutes=5)
        ).isoformat()

        # Mock the OBO token refresh to prevent real HTTP requests
        with patch.object(self.middleware, "_refresh_obo_token") as mock_refresh_obo:
            # Call refresh method
            self.middleware._refresh_tokens(self.request)

            # Check that access token was updated but refresh token remains the same
            self.assertEqual(
                _decrypt_token(self.request.session["ADFS_ACCESS_TOKEN"]),
                "new_access_token",
            )
            self.assertEqual(
                _decrypt_token(self.request.session["ADFS_REFRESH_TOKEN"]),
                "old_refresh_token",
            )

    @patch("django_auth_adfs.backend.AdfsBaseBackend")
    def test_refresh_obo_token_success(self, mock_backend_class):
        """Test successful OBO token refresh"""
        # Set up mock backend
        mock_backend = Mock()
        mock_backend.get_obo_access_token.return_value = "new_obo_token"
        mock_backend_class.return_value = mock_backend

        # Ensure OBO token storage is enabled
        self.middleware.store_obo_token = True

        # Set up session with expired OBO token but valid access token
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("valid_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
            "valid_refresh_token"
        )
        self.request.session["ADFS_OBO_ACCESS_TOKEN"] = _encrypt_token(
            "expired_obo_token"
        )
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now() + datetime.timedelta(hours=1)
        ).isoformat()
        self.request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now() - datetime.timedelta(minutes=5)
        ).isoformat()

        # Call handle token refresh directly
        self.middleware._handle_token_refresh(self.request)

        # Verify the backend was called with the correct token
        mock_backend.get_obo_access_token.assert_called_once_with("valid_access_token")

        # Verify the new token was stored in the session
        self.assertEqual(
            _decrypt_token(self.request.session["ADFS_OBO_ACCESS_TOKEN"]),
            "new_obo_token",
        )
        self.assertTrue("ADFS_OBO_TOKEN_EXPIRES_AT" in self.request.session)

    def test_refresh_obo_token_failure(self):
        """Test failed OBO token refresh"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"

        # Store original session state to verify it's not modified
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        with patch("django_auth_adfs.backend.AdfsBaseBackend") as mock_backend:
            mock_backend.return_value.get_obo_access_token.return_value = None

            self.middleware._refresh_obo_token(self.request)

            # Verify session not modified
            self.assertFalse("ADFS_OBO_ACCESS_TOKEN" in self.request.session)
            self.assertEqual(dict(self.request.session), original_session_data)
            self.assertFalse(self.request.session.modified)

    def test_obo_token_without_access_token(self):
        """Test OBO token handling when access token is missing"""
        # Only OBO token exists
        self.request.session["ADFS_OBO_ACCESS_TOKEN"] = "obo_token"
        self.request.session["ADFS_OBO_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now().isoformat()
        )
        # No ADFS_ACCESS_TOKEN

        # Store original session state to verify it's not modified
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        self.middleware._refresh_obo_token(self.request)

        # Verify session not modified
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    # Group 5: Authentication Signal Tests

    def test_capture_tokens_from_auth(self):
        """Test capturing tokens during authentication"""
        sender = Mock()
        sender.access_token = "sender_access_token"
        sender.get_obo_access_token.return_value = "obo_token"

        adfs_response = {
            "access_token": "response_access_token",
            "refresh_token": "response_refresh_token",
            "expires_in": 3600,
        }

        self.middleware._capture_tokens_from_auth(
            sender=sender, user=self.user, claims={}, adfs_response=adfs_response
        )

        # Check user object has temporary token attributes
        self.assertEqual(getattr(self.user, "access_token"), "sender_access_token")
        self.assertEqual(getattr(self.user, "refresh_token"), "response_refresh_token")
        self.assertTrue(hasattr(self.user, "token_expires_at"))
        self.assertEqual(getattr(self.user, "obo_access_token"), "obo_token")
        self.assertTrue(hasattr(self.user, "obo_token_expires_at"))

    def test_capture_tokens_from_adfs_response_only(self):
        """Test capturing tokens when they're only in the ADFS response, not on sender"""
        sender = Mock(spec=[])  # Create a mock without access_token attribute
        # Ensure get_obo_access_token is available but returns None
        sender.get_obo_access_token = Mock(return_value=None)

        adfs_response = {
            "access_token": "response_access_token",
            "refresh_token": "response_refresh_token",
            "expires_in": 3600,
        }

        self.middleware._capture_tokens_from_auth(
            sender=sender, user=self.user, claims={}, adfs_response=adfs_response
        )

        # Check user object has temporary token attributes from adfs_response
        self.assertEqual(getattr(self.user, "access_token"), "response_access_token")
        self.assertEqual(getattr(self.user, "refresh_token"), "response_refresh_token")
        self.assertTrue(hasattr(self.user, "token_expires_at"))
        # No OBO token should be set
        self.assertFalse(hasattr(self.user, "obo_access_token"))

    # Group 6: Middleware Call Tests

    def test_middleware_call_with_authenticated_user(self):
        """Test the complete middleware request/response cycle with authenticated user"""
        # Set up user with tokens
        setattr(self.user, "access_token", "test_access_token")
        setattr(self.user, "refresh_token", "test_refresh_token")
        setattr(
            self.user,
            "token_expires_at",
            datetime.datetime.now() + datetime.timedelta(hours=1),
        )

        # Create request with authenticated user
        request = self.factory.get("/")
        request.user = self.user
        request.session = SessionStore()

        # Call middleware
        response = self.middleware(request)

        # Check that tokens were stored in session
        self.assertEqual(
            _decrypt_token(request.session["ADFS_ACCESS_TOKEN"]), "test_access_token"
        )
        self.assertEqual(
            _decrypt_token(request.session["ADFS_REFRESH_TOKEN"]), "test_refresh_token"
        )
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in request.session)

    def test_middleware_post_response_token_storage(self):
        """Test tokens added during view processing are stored after response"""

        def get_response_with_token_addition(request):
            # Simulate a view that adds tokens to the user
            setattr(request.user, "access_token", "view_added_token")
            setattr(
                request.user,
                "token_expires_at",
                datetime.datetime.now() + datetime.timedelta(hours=1),
            )
            return Mock()

        # Create middleware with our custom get_response
        middleware = TokenLifecycleMiddleware(get_response_with_token_addition)

        # Create request with authenticated user
        request = self.factory.get("/")
        request.user = self.user
        request.session = SessionStore()

        # Call middleware
        response = middleware(request)

        # Check that tokens were stored in session
        self.assertEqual(
            _decrypt_token(request.session["ADFS_ACCESS_TOKEN"]), "view_added_token"
        )
        self.assertTrue("ADFS_TOKEN_EXPIRES_AT" in request.session)

    def test_middleware_without_user(self):
        """Test middleware behavior when request has no user"""
        request = self.factory.get("/")
        request.session = SessionStore()

        response = self.middleware(request)
        # Should not raise any errors
        self.assertEqual(response, request)

    def test_middleware_with_unauthenticated_user(self):
        """Test middleware behavior with unauthenticated user"""
        request = self.factory.get("/")
        request.user = Mock(is_authenticated=False)
        request.session = SessionStore()

        with patch.object(self.middleware, "_handle_token_refresh") as mock_refresh:
            response = self.middleware(request)
            mock_refresh.assert_not_called()

    # Group 7: Error Handling Tests

    def test_handle_malformed_expiry_time(self):
        """Test handling of malformed expiry time in session"""
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_REFRESH_TOKEN"] = "test_refresh_token"
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = "invalid_datetime"

        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        # Should handle gracefully without error
        self.middleware._handle_token_refresh(self.request)

        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_handle_incomplete_token_state(self):
        """Test handling when only some token data exists in session"""
        # Only access token, no refresh token
        self.request.session["ADFS_ACCESS_TOKEN"] = "test_access_token"
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = (
            datetime.datetime.now().isoformat()
        )
        # Missing ADFS_REFRESH_TOKEN

        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        self.middleware._handle_token_refresh(self.request)

        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_handle_malformed_tokens(self):
        """Test handling of malformed/corrupt token data in session"""
        # Invalid token format
        self.request.session["ADFS_ACCESS_TOKEN"] = {"malformed": "data"}
        self.request.session["ADFS_REFRESH_TOKEN"] = None
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = "not-a-date"

        # Store original session state to verify it's not modified inappropriately
        original_session_data = dict(self.request.session)
        self.request.session.modified = False

        self.middleware._handle_token_refresh(self.request)

        # Verify session wasn't modified inappropriately
        self.assertEqual(dict(self.request.session), original_session_data)
        self.assertFalse(self.request.session.modified)

    def test_disabled_obo_token_functionality(self):
        """Test that OBO token functionality is disabled when STORE_OBO_TOKEN is False"""
        # Set up a user with an access token and OBO token
        self.user.access_token = "test_access_token"
        self.user.obo_access_token = "test_obo_token"

        # Patch the middleware to disable OBO token storage
        with patch.object(self.middleware, "store_obo_token", False):
            # Store tokens from user
            self.middleware._store_tokens_from_user(self.request)

            # Verify access token is stored but OBO token is not
            self.assertTrue("ADFS_ACCESS_TOKEN" in self.request.session)
            self.assertFalse("ADFS_OBO_ACCESS_TOKEN" in self.request.session)

            # Verify get_obo_access_token returns None when disabled
            with patch("django_auth_adfs.utils.settings") as mock_settings:
                mock_settings.STORE_OBO_TOKEN = False
                self.assertIsNone(get_obo_access_token(self.request))

    def test_token_encryption(self):
        """Test that tokens are properly encrypted and decrypted"""
        # Test encryption and decryption directly
        original_token = "test_access_token"
        encrypted_token = _encrypt_token(original_token)

        # Verify the token is encrypted (should be different from original)
        self.assertNotEqual(original_token, encrypted_token)

        # Verify the token can be decrypted back to the original
        decrypted_token = _decrypt_token(encrypted_token)
        self.assertEqual(original_token, decrypted_token)

        # Test the middleware stores encrypted tokens
        self.user.access_token = original_token
        self.middleware._store_tokens_from_user(self.request)

        # Verify the token in the session is encrypted
        session_token = self.request.session.get("ADFS_ACCESS_TOKEN")
        self.assertNotEqual(original_token, session_token)

        # Test the utility function decrypts the token
        retrieved_token = get_access_token(self.request)
        self.assertEqual(original_token, retrieved_token)

        # Test with OBO token
        original_obo_token = "test_obo_token"
        self.user.obo_access_token = original_obo_token
        self.middleware._store_tokens_from_user(self.request)

        # Verify the OBO token in the session is encrypted
        session_obo_token = self.request.session.get("ADFS_OBO_ACCESS_TOKEN")
        self.assertNotEqual(original_obo_token, session_obo_token)

        # Test the utility function decrypts the OBO token
        retrieved_obo_token = get_obo_access_token(self.request)
        self.assertEqual(original_obo_token, retrieved_obo_token)

    @override_settings(TOKEN_ENCRYPTION_SALT="custom-salt-for-testing")
    def test_custom_encryption_salt(self):
        """Test that custom encryption salt changes the encrypted token value"""
        # First, encrypt a token with the default salt
        original_token = "test_access_token"
        default_encrypted_token = _encrypt_token(original_token)

        # Now, encrypt the same token with a custom salt (set via override_settings)
        with patch("django_auth_adfs.utils.settings") as mock_settings:
            mock_settings.TOKEN_ENCRYPTION_SALT = "custom-salt-for-testing"
            custom_encrypted_token = _encrypt_token(original_token)

        # The encrypted tokens should be different due to different salts
        self.assertNotEqual(default_encrypted_token, custom_encrypted_token)

        # But both should decrypt to the original token when using the correct salt
        with patch("django_auth_adfs.utils.settings") as mock_settings:
            mock_settings.TOKEN_ENCRYPTION_SALT = "custom-salt-for-testing"
            decrypted_token = _decrypt_token(custom_encrypted_token)

        self.assertEqual(original_token, decrypted_token)

        # A token encrypted with one salt should not be decryptable with another
        with patch("django_auth_adfs.utils.settings") as mock_settings:
            mock_settings.TOKEN_ENCRYPTION_SALT = "different-salt"
            # The function catches exceptions and returns None, so check for None
            self.assertIsNone(_decrypt_token(custom_encrypted_token))

    @patch("django_auth_adfs.middleware.provider_config")
    def test_refresh_token_failure_with_logout(self, mock_provider_config):
        """Test token refresh failure with LOGOUT_ON_TOKEN_REFRESH_FAILURE enabled"""
        # Setup
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("test_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
            "test_refresh_token"
        )
        expires_at = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        # Mock the response from the token endpoint
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid refresh token"
        mock_provider_config.session.post.return_value = mock_response

        # Enable the setting
        with patch("django_auth_adfs.middleware.settings") as mock_settings:
            mock_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE = True
            mock_settings.CLIENT_ID = "test_client_id"
            mock_settings.CLIENT_SECRET = "test_client_secret"
            mock_settings.TIMEOUT = 5

            # Mock the logout function
            with patch("django.contrib.auth.logout") as mock_logout:
                self.middleware._refresh_tokens(self.request)

                # Verify logout was called
                mock_logout.assert_called_once_with(self.request)

    @patch("django_auth_adfs.middleware.provider_config")
    def test_refresh_token_failure_without_logout(self, mock_provider_config):
        """Test token refresh failure with LOGOUT_ON_TOKEN_REFRESH_FAILURE disabled"""
        # Setup
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("test_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
            "test_refresh_token"
        )
        expires_at = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        # Mock the response from the token endpoint
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid refresh token"
        mock_provider_config.session.post.return_value = mock_response

        # Disable the setting (default)
        with patch("django_auth_adfs.middleware.settings") as mock_settings:
            mock_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE = False
            mock_settings.CLIENT_ID = "test_client_id"
            mock_settings.CLIENT_SECRET = "test_client_secret"
            mock_settings.TIMEOUT = 5

            # Mock the logout function
            with patch("django.contrib.auth.logout") as mock_logout:
                self.middleware._refresh_tokens(self.request)

                # Verify logout was not called
                mock_logout.assert_not_called()

    @patch("django_auth_adfs.middleware.provider_config")
    def test_refresh_token_exception_with_logout(self, mock_provider_config):
        """Test token refresh exception with LOGOUT_ON_TOKEN_REFRESH_FAILURE enabled"""
        # Setup
        self.request.session["ADFS_ACCESS_TOKEN"] = _encrypt_token("test_access_token")
        self.request.session["ADFS_REFRESH_TOKEN"] = _encrypt_token(
            "test_refresh_token"
        )
        expires_at = datetime.datetime.now() - datetime.timedelta(minutes=5)
        self.request.session["ADFS_TOKEN_EXPIRES_AT"] = expires_at.isoformat()

        # Make the request raise an exception
        mock_provider_config.session.post.side_effect = Exception("Connection error")

        # Enable the setting
        with patch("django_auth_adfs.middleware.settings") as mock_settings:
            mock_settings.LOGOUT_ON_TOKEN_REFRESH_FAILURE = True
            mock_settings.CLIENT_ID = "test_client_id"
            mock_settings.CLIENT_SECRET = "test_client_secret"
            mock_settings.TIMEOUT = 5

            # Mock the logout function
            with patch("django.contrib.auth.logout") as mock_logout:
                self.middleware._refresh_tokens(self.request)

                # Verify logout was called
                mock_logout.assert_called_once_with(self.request)
