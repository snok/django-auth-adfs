"""
Utility functions for django-auth-adfs.

Only relevant if you are using the Token Lifecycle Middleware.
"""

import logging
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django.conf import settings as django_settings
from django_auth_adfs.config import settings

logger = logging.getLogger("django_auth_adfs")


def _get_encryption_key():
    """
    Derive a Fernet encryption key from Django's SECRET_KEY.

    The salt can be customized through the TOKEN_ENCRYPTION_SALT setting.

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


def _encrypt_token(token):
    """
    Encrypt a token using Django's SECRET_KEY.

    Args:
        token (str): The token to encrypt

    Returns:
        str: The encrypted token as a string
    """
    if not token:
        return None

    try:
        key = _get_encryption_key()
        f = Fernet(key)
        encrypted_token = f.encrypt(token.encode())
        return encrypted_token.decode()
    except Exception as e:
        logger.error(f"Error encrypting token: {e}")
        return None


def _decrypt_token(encrypted_token):
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
        key = _get_encryption_key()
        f = Fernet(key)
        decrypted_token = f.decrypt(encrypted_token.encode())
        return decrypted_token.decode()
    except Exception as e:
        logger.error(f"Error decrypting token: {e}")
        return None


def _is_signed_cookies_disabled():
    """
    Check if token storage is disabled for signed_cookies session backend
    """
    using_signed_cookies = (
        django_settings.SESSION_ENGINE
        == "django.contrib.sessions.backends.signed_cookies"
    )
    return using_signed_cookies


def get_access_token(request):
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

    if _is_signed_cookies_disabled():
        logger.debug("Token retrieval from signed_cookies session is disabled")
        return None

    encrypted_token = request.session.get("ADFS_ACCESS_TOKEN")
    return _decrypt_token(encrypted_token)


def get_obo_access_token(request):
    """
    Get the current OBO (On-Behalf-Of) access token for Microsoft Graph API from the session.

    The token is automatically decrypted before being returned.

    Args:
        request: The current request object

    Returns:
        str: The OBO access token or None if not available
    """
    if not hasattr(request, "session"):
        return None

    if _is_signed_cookies_disabled():
        logger.debug("Token retrieval from signed_cookies session is disabled")
        return None

    store_obo_token = getattr(settings, "STORE_OBO_TOKEN", True)
    if not store_obo_token:
        logger.debug("OBO token storage is disabled")
        return None

    encrypted_token = request.session.get("ADFS_OBO_ACCESS_TOKEN")
    return _decrypt_token(encrypted_token)
