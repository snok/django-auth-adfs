"""
Token management for django-auth-adfs.

This module provides a centralized way to manage tokens for django-auth-adfs.
"""

import logging
import base64
import datetime

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django.conf import settings as django_settings
from django.contrib.auth import logout
from django_auth_adfs.config import settings, provider_config

logger = logging.getLogger("django_auth_adfs")


class TokenManager:
    """
    Centralized manager for token lifecycle operations.
    
    This class handles:
    - Token storage during authentication
    - Token encryption/decryption
    - Token refresh
    - Token retrieval
    - OBO token management
    
    It's designed to be lightweight when not actively performing operations,
    and to handle all token operations in a safe, transparent, and error-free manner.
    """
    
    # Session key constants
    ACCESS_TOKEN_KEY = "ADFS_ACCESS_TOKEN"
    REFRESH_TOKEN_KEY = "ADFS_REFRESH_TOKEN"
    TOKEN_EXPIRES_AT_KEY = "ADFS_TOKEN_EXPIRES_AT"
    OBO_ACCESS_TOKEN_KEY = "ADFS_OBO_ACCESS_TOKEN"
    OBO_TOKEN_EXPIRES_AT_KEY = "ADFS_OBO_TOKEN_EXPIRES_AT"
    
    def __init__(self):
        """Initialize the TokenManager with settings."""
        # Load settings
        self.refresh_threshold = getattr(settings, "TOKEN_REFRESH_THRESHOLD", 300)
        self.store_obo_token = getattr(settings, "STORE_OBO_TOKEN", True)
        self.logout_on_refresh_failure = getattr(settings, "LOGOUT_ON_TOKEN_REFRESH_FAILURE", False)
        
        # Check if using signed cookies
        self.using_signed_cookies = (
            django_settings.SESSION_ENGINE == "django.contrib.sessions.backends.signed_cookies"
        )
        
        if self.using_signed_cookies:
            logger.warning(
                "TokenManager: Storing tokens in signed cookies is not recommended for security "
                "reasons and cookie size limitations. Token storage will be disabled."
            )
    
    def is_middleware_enabled(self):
        """Check if the TokenLifecycleMiddleware is enabled."""
        try:
            for middleware in django_settings.MIDDLEWARE:
                if middleware.endswith('TokenLifecycleMiddleware'):
                    return True
            return False
        except Exception as e:
            logger.warning(f"Error checking if middleware is enabled: {e}")
            return False
    
    def should_store_tokens(self, request):
        """
        Check if tokens should be stored in the session.
        
        Tokens are stored if:
        1. We have a request with a session
        2. The TokenLifecycleMiddleware is enabled
        3. We're not using signed cookies
        
        Args:
            request: The current request object
            
        Returns:
            bool: True if tokens should be stored, False otherwise
        """
        if not request or not hasattr(request, "session"):
            return False
            
        if self.using_signed_cookies:
            return False
            
        return self.is_middleware_enabled()
    
    def _get_encryption_key(self):
        """
        Derive a Fernet encryption key from Django's SECRET_KEY.
        
        Returns:
            bytes: A 32-byte key suitable for Fernet encryption
        """
        # Use Django's SECRET_KEY to derive a suitable encryption key
        default_salt = b"django_auth_adfs_token_encryption"
        salt = getattr(settings, "TOKEN_ENCRYPTION_SALT", default_salt)
        
        if isinstance(salt, str):
            salt = salt.encode()
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(django_settings.SECRET_KEY.encode()))
        return key
    
    def encrypt_token(self, token):
        """
        Encrypt a token using Django's SECRET_KEY.
        
        Args:
            token (str): The token to encrypt
            
        Returns:
            str: The encrypted token as a string or None if encryption fails
        """
        if not token:
            return None
            
        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            encrypted_token = f.encrypt(token.encode())
            return encrypted_token.decode()
        except Exception as e:
            logger.error(f"Error encrypting token: {e}")
            return None
    
    def decrypt_token(self, encrypted_token):
        """
        Decrypt a token that was encrypted using Django's SECRET_KEY.
        
        Args:
            encrypted_token (str): The encrypted token
            
        Returns:
            str: The decrypted token or None if decryption fails
        """
        if not encrypted_token:
            return None
            
        try:
            key = self._get_encryption_key()
            f = Fernet(key)
            decrypted_token = f.decrypt(encrypted_token.encode())
            return decrypted_token.decode()
        except Exception as e:
            logger.error(f"Error decrypting token: {e}")
            return None
    
    def get_access_token(self, request):
        """
        Get the current access token from the session.
        
        The token is automatically decrypted before being returned.
        
        Args:
            request: The current request object
            
        Returns:
            str: The access token or None if not available
        """
        if not hasattr(request, "session"):
            return None
            
        if self.using_signed_cookies:
            logger.debug("Token retrieval from signed_cookies session is disabled")
            return None
            
        encrypted_token = request.session.get(self.ACCESS_TOKEN_KEY)
        return self.decrypt_token(encrypted_token)
    
    def get_obo_access_token(self, request):
        """
        Get the current OBO access token from the session.
        
        The token is automatically decrypted before being returned.
        
        Args:
            request: The current request object
            
        Returns:
            str: The OBO access token or None if not available
        """
        if not hasattr(request, "session"):
            return None
            
        if self.using_signed_cookies:
            logger.debug("Token retrieval from signed_cookies session is disabled")
            return None
            
        if not self.store_obo_token:
            logger.debug("OBO token storage is disabled")
            return None
            
        encrypted_token = request.session.get(self.OBO_ACCESS_TOKEN_KEY)
        return self.decrypt_token(encrypted_token)
    
    def store_tokens(self, request, access_token, adfs_response=None):
        """
        Store tokens in the session.
        
        Args:
            request: The current request object
            access_token (str): The access token to store
            adfs_response (dict, optional): The full response from ADFS containing refresh token and expiration
            
        Returns:
            bool: True if tokens were stored, False otherwise
        """
        if not self.should_store_tokens(request):
            return False
            
        try:
            session_modified = False
            
            # Store access token
            encrypted_token = self.encrypt_token(access_token)
            if encrypted_token:
                request.session[self.ACCESS_TOKEN_KEY] = encrypted_token
                session_modified = True
            
            # Store refresh token
            if adfs_response and "refresh_token" in adfs_response:
                refresh_token = adfs_response["refresh_token"]
                encrypted_token = self.encrypt_token(refresh_token)
                if encrypted_token:
                    request.session[self.REFRESH_TOKEN_KEY] = encrypted_token
                    session_modified = True
            
            # Store token expiration
            if adfs_response and "expires_in" in adfs_response:
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(adfs_response["expires_in"])
                )
                request.session[self.TOKEN_EXPIRES_AT_KEY] = expires_at.isoformat()
                session_modified = True
            
            # Store OBO token if enabled
            if self.store_obo_token:
                try:
                    # Import here to avoid circular imports
                    from django_auth_adfs.backend import AdfsBaseBackend
                    
                    backend = AdfsBaseBackend()
                    obo_token = backend.get_obo_access_token(access_token)
                    if obo_token:
                        encrypted_token = self.encrypt_token(obo_token)
                        if encrypted_token:
                            request.session[self.OBO_ACCESS_TOKEN_KEY] = encrypted_token
                            obo_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
                            request.session[self.OBO_TOKEN_EXPIRES_AT_KEY] = obo_expires_at.isoformat()
                            session_modified = True
                except Exception as e:
                    logger.warning(f"Error getting OBO token: {e}")
            
            if session_modified:
                request.session.modified = True
                logger.debug("Stored tokens in session")
                return True
                
            return False
                
        except Exception as e:
            logger.warning(f"Error storing tokens in session: {e}")
            return False
    
    def check_token_expiration(self, request):
        """
        Check if tokens need to be refreshed and refresh them if needed.
        
        Args:
            request: The current request object
            
        Returns:
            bool: True if tokens were checked, False otherwise
        """
        if not hasattr(request, "user") or not request.user.is_authenticated:
            return False
            
        if self.using_signed_cookies:
            return False
            
        try:
            if self.TOKEN_EXPIRES_AT_KEY not in request.session:
                return False
                
            # Check if token is about to expire
            expires_at = datetime.datetime.fromisoformat(request.session[self.TOKEN_EXPIRES_AT_KEY])
            remaining = expires_at - datetime.datetime.now()
            
            if remaining.total_seconds() < self.refresh_threshold:
                logger.debug("Token is about to expire. Refreshing...")
                self.refresh_tokens(request)
                
            # Check if OBO token is about to expire
            if self.store_obo_token and self.OBO_TOKEN_EXPIRES_AT_KEY in request.session:
                obo_expires_at = datetime.datetime.fromisoformat(request.session[self.OBO_TOKEN_EXPIRES_AT_KEY])
                obo_remaining = obo_expires_at - datetime.datetime.now()
                
                if obo_remaining.total_seconds() < self.refresh_threshold:
                    logger.debug("OBO token is about to expire. Refreshing...")
                    self.refresh_obo_token(request)
                    
            return True
                
        except Exception as e:
            logger.warning(f"Error checking token expiration: {e}")
            return False
    
    def refresh_tokens(self, request):
        """
        Refresh the access token using the refresh token.
        
        Args:
            request: The current request object
            
        Returns:
            bool: True if tokens were refreshed, False otherwise
        """
        if self.using_signed_cookies:
            return False
            
        if self.REFRESH_TOKEN_KEY not in request.session:
            return False
            
        try:
            refresh_token = self.decrypt_token(request.session[self.REFRESH_TOKEN_KEY])
            if not refresh_token:
                logger.warning("Failed to decrypt refresh token")
                return False
                
            provider_config.load_config()
            
            data = {
                "grant_type": "refresh_token",
                "client_id": settings.CLIENT_ID,
                "refresh_token": refresh_token,
            }
            
            if settings.CLIENT_SECRET:
                data["client_secret"] = settings.CLIENT_SECRET
                
            # Ensure token_endpoint is a string
            token_endpoint = provider_config.token_endpoint
            if token_endpoint is None:
                logger.error("Token endpoint is None, cannot refresh tokens")
                return False
                
            response = provider_config.session.post(
                token_endpoint, data=data, timeout=settings.TIMEOUT
            )
            
            if response.status_code == 200:
                token_data = response.json()
                request.session[self.ACCESS_TOKEN_KEY] = self.encrypt_token(
                    token_data["access_token"]
                )
                request.session[self.REFRESH_TOKEN_KEY] = self.encrypt_token(
                    token_data["refresh_token"]
                )
                expires_at = datetime.datetime.now() + datetime.timedelta(
                    seconds=int(token_data["expires_in"])
                )
                request.session[self.TOKEN_EXPIRES_AT_KEY] = expires_at.isoformat()
                request.session.modified = True
                logger.debug("Refreshed tokens successfully")
                
                # Also refresh the OBO token if needed
                if self.store_obo_token:
                    self.refresh_obo_token(request)
                    
                return True
            else:
                logger.warning(
                    f"Failed to refresh token: {response.status_code} {response.text}"
                )
                if self.logout_on_refresh_failure:
                    logger.info("Logging out user due to token refresh failure")
                    logout(request)
                return False
                
        except Exception as e:
            logger.exception(f"Error refreshing tokens: {e}")
            if self.logout_on_refresh_failure:
                logger.info("Logging out user due to token refresh error")
                logout(request)
            return False
    
    def refresh_obo_token(self, request):
        """
        Refresh the OBO token for Microsoft Graph API.
        
        Args:
            request: The current request object
            
        Returns:
            bool: True if OBO token was refreshed, False otherwise
        """
        if not self.store_obo_token:
            return False
            
        if self.using_signed_cookies:
            return False
            
        if self.ACCESS_TOKEN_KEY not in request.session:
            return False
            
        try:
            provider_config.load_config()
            
            access_token = self.decrypt_token(request.session[self.ACCESS_TOKEN_KEY])
            if not access_token:
                logger.warning("Failed to decrypt access token")
                return False
                
            # Import here to avoid circular imports
            from django_auth_adfs.backend import AdfsBaseBackend
            
            backend = AdfsBaseBackend()
            obo_token = backend.get_obo_access_token(access_token)
            
            if obo_token:
                request.session[self.OBO_ACCESS_TOKEN_KEY] = self.encrypt_token(obo_token)
                obo_expires_at = datetime.datetime.now() + datetime.timedelta(hours=1)
                request.session[self.OBO_TOKEN_EXPIRES_AT_KEY] = obo_expires_at.isoformat()
                request.session.modified = True
                logger.debug("Refreshed OBO token successfully")
                return True
                
            return False
                
        except Exception as e:
            logger.warning(f"Error refreshing OBO token: {e}")
            return False
    
    def clear_tokens(self, request):
        """
        Clear all tokens from the session.
        
        Args:
            request: The current request object
            
        Returns:
            bool: True if tokens were cleared, False otherwise
        """
        if not hasattr(request, "session"):
            return False
            
        try:
            session_modified = False
            
            for key in [
                self.ACCESS_TOKEN_KEY,
                self.REFRESH_TOKEN_KEY,
                self.TOKEN_EXPIRES_AT_KEY,
                self.OBO_ACCESS_TOKEN_KEY,
                self.OBO_TOKEN_EXPIRES_AT_KEY
            ]:
                if key in request.session:
                    del request.session[key]
                    session_modified = True
                    
            if session_modified:
                request.session.modified = True
                logger.debug("Cleared tokens from session")
                return True
                
            return False
                
        except Exception as e:
            logger.warning(f"Error clearing tokens from session: {e}")
            return False


# Create a singleton instance
token_manager = TokenManager() 