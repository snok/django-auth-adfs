Token Lifecycle Middleware
==========================

Traditionally, django-auth-adfs is used **exclusively** as an authentication solution - it handles user authentication
via ADFS/Azure AD and maps claims to Django users. It doesn't really care about the access tokens from Azure/ADFS after you've been authenticated.

The Token Lifecycle Middleware extends django-auth-adfs beyond pure authentication to also handle the complete lifecycle of access tokens
after the authentication process. This creates a more integrated approach where:

* The same application registration handles both authentication and resource access
* Tokens obtained during authentication are managed and refreshed automatically
* The application can make delegated API calls on behalf of the user
* The middleware can optionally log out users when token refresh fails

How it works
------------

The ``TokenLifecycleMiddleware`` handles the entire token lifecycle:

1. **Initial Token Capture**: Uses the ``post_authenticate`` signal to capture tokens during authentication
2. **Token Storage**: Automatically stores tokens in the users session after successful authentication
3. **Token Refresh**: Checks if the access token is about to expire and refreshes it if needed
4. **Optional Security Enforcement**: Can be configured to log out users when token refresh fails
5. **Session Management**: Keeps the session updated with the latest tokens
6. **OBO Token Management**: Handles On-Behalf-Of tokens for Microsoft Graph API access

Read more: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow#protocol-diagram


.. warning::
    The Token Lifecycle Middleware is a new feature in django-auth-adfs and is considered experimental.
    Please be aware:

    **Currently no community support is guaranteed to be available for this feature**

    We recommend thoroughly testing this feature in your specific environment before deploying to production.

    Consider enabling the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting,
    which allows you to log out users when token refresh fails.


Configuration
-------------

To enable the token lifecycle middleware, add it to your ``MIDDLEWARE`` setting in your Django settings file:

.. code-block:: python

    MIDDLEWARE = [
        # ... other middleware
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django_auth_adfs.middleware.TokenLifecycleMiddleware',  # Add this line
        # ... other middleware
    ]

.. important::
    The middleware must be placed after the ``SessionMiddleware`` and ``AuthenticationMiddleware``.


You can configure the token lifecycle behavior with these settings in your Django settings file:

.. code-block:: python

    AUTH_ADFS = {
        # other settings

        # Number of seconds before expiration to refresh (default: 300, i.e., 5 minutes)
        "TOKEN_REFRESH_THRESHOLD": 300,

        # Enable or disable OBO token storage for Microsoft Graph API (default: True)
        "STORE_OBO_TOKEN": True,

        # Custom salt for token encryption (optional)
        # If not specified, a default salt is used
        "TOKEN_ENCRYPTION_SALT": "your-custom-salt-string",

        # Automatically log out users when token refresh fails (default: False)
        "LOGOUT_ON_TOKEN_REFRESH_FAILURE": False,
    }

.. warning::
    If you change the ``TOKEN_ENCRYPTION_SALT`` after tokens have been stored in sessions, those tokens will no longer be decryptable.
    This effectively invalidates all existing tokens, requiring users to re-authenticate.

    Consider this when deploying changes to the salt in production environments.

.. note::
    By default (``STORE_OBO_TOKEN = True``), the middleware will automatically request and store OBO tokens
    for Microsoft Graph API access. If your application doesn't need to access Microsoft Graph API,
    you can set ``STORE_OBO_TOKEN = False`` to disable this functionality completely.
    See `the OBO token configuration section <#disabling-obo-token-functionality>`_ for more details.

Considerations
--------------

- The middleware will automatically capture and store tokens during authentication using signals.
- You don't need to modify your views or authentication backends to store tokens.
- Token refresh only works for authenticated users.
- If the refresh token is invalid or expired, the middleware will not be able to refresh the access token.
- By default, the middleware will not log the user out if token refresh fails, but this behavior can be changed with the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting.
- The middleware will not store tokens in the session when using the ``signed_cookies`` session backend by default.
- OBO token storage is enabled by default but can be disabled with the ``STORE_OBO_TOKEN`` setting.
- Using the OBO token versus the regular access token is dependent on the resources you are accessing and the permissions granted to your ADFS/Azure AD application. See `the token types section <#understanding-access-tokens-vs-obo-tokens>`_ for more details.

**Token Refresh Failures**

By default, when token refresh fails, the middleware logs the error but allows the user to continue using the application until their session expires naturally. This behavior can be changed with the ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting:

- When set to ``False`` (default), users remain logged in even if their tokens can't be refreshed
- When set to ``True``, users are automatically logged out when token refresh fails

When a user's account is disabled in Azure AD/ADFS, their existing Django sessions will remain active by default until they expire naturally. This can create a security gap where revoked users maintain access to your application.

The ``LOGOUT_ON_TOKEN_REFRESH_FAILURE`` setting provides an option to address this concern by allowing you to configure the middleware to automatically log out users when their token refresh fails, which happens when their account has been disabled in the identity provider.

**Existing Sessions**

When deploying the Token Lifecycle Middleware to an existing application with active user sessions, be aware of the following:

The middleware only captures tokens during the authentication process. Existing authenticated sessions won't have tokens stored in them, which means:

- Users with existing sessions won't have access to token-dependent features until they re-authenticate
- Utility functions like ``get_access_token()`` and ``get_obo_access_token()`` will return ``None`` for these sessions
- API calls that depend on these tokens will fail for existing sessions

The best approach is to ensure that all users re-authenticate after the middleware is deployed.

Azure AD Application Configuration
----------------------------------

When using the Token Lifecycle Middleware, your Azure AD application registration needs additional permissions
beyond those required for simple authentication. This extends the standard authentication-only setup described in the :doc:`azure_ad_config_guide` with additional
API permissions needed for delegated access.

.. important::
    Your Django application's session cookie age must be set to a value that is less than that of your ADFS/Azure AD application's refresh token lifetime.

    If a users refresh token has expired, the user will be required to re-authenticate to continue making delegated requests.

Security Overview
-----------------------

**Token Encryption**

Tokens are automatically encrypted before being stored in the session and decrypted when they are retrieved.
The encryption is handled transparently by the middleware and utility functions. This provides an additional layer of security:

- **Always Enabled**: Token encryption is always enabled and cannot be disabled
- **Encryption Method**: Tokens are encrypted using the Fernet symmetric encryption algorithm
- **Encryption Key**: The key is derived from Django's ``SECRET_KEY`` using PBKDF2
- **Customizable Salt**: You can customize the encryption salt using the ``TOKEN_ENCRYPTION_SALT`` setting
- **Transparent Operation**: Encryption and decryption happen automatically when tokens are stored or retrieved


**Signed Cookies Session Backend Restriction**

The middleware will not store tokens in the session when using Django's ``signed_cookies`` session backend:

.. code-block:: python

    # This will not work with the token lifecycle middleware
    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'

This is for a few reasons:

1. **Size Limitations**: Cookies have size limitations (typically 4KB), which may be exceeded by tokens
2. **Security Risks**: Storing sensitive tokens in cookies increases the risk of token theft
3. **Performance**: Large cookies are sent with every request, increasing bandwidth usage

If you're using the ``signed_cookies`` session backend and need token storage, you won't be able to use the token lifecycle middleware.

.. note::
    This restriction only applies to the ``signed_cookies`` session backend. For other session backends (database, cache, file),
    tokens are stored securely on the server and only a session ID is stored in the cookie.

**Automatic OBO Token Acquisition**

By default, the middleware automatically requests OBO tokens during authentication. If your application doesn't need OBO tokens, you can disable this behavior to reduce unnecessary token requests (see `the OBO token configuration section <#disabling-obo-token-functionality>`_ for more details).

Disabling OBO Token Functionality
---------------------------------

By default, the Token Lifecycle Middleware automatically requests and stores OBO tokens for Microsoft Graph API access. If you don't need this functionality (for example, if your application doesn't interact with Microsoft Graph API), you can disable it completely:

.. code-block:: python

    # In your Django settings.py
    AUTH_ADFS = {
        "STORE_OBO_TOKEN": False,
    }

When this setting is ``False``:

1. The middleware will not request OBO tokens during authentication
2. The middleware will not store OBO tokens in the session
3. The middleware will not refresh OBO tokens
4. The ``get_obo_access_token`` utility function will always return ``None``

Note that disabling OBO tokens doesn't affect the regular access token functionality. Your application will still be able to use the access token obtained during authentication for its own resources and APIs that directly trust your application.

See `the token types section <#understanding-access-tokens-vs-obo-tokens>`_ for more details.

Accessing Tokens in Your Views
------------------------------

When building views that need to make requests using the Azure AD/ADFS tokens, you'll need to access the tokens stored in the session.

Since tokens are encrypted in the session, Token Lifecycle Middleware provides utility functions in the ``django_auth_adfs.utils`` module to help you access tokens safely:

.. code-block:: python

    # For your own APIs or APIs that trust your application directly
    from django_auth_adfs.utils import get_access_token

    # For Microsoft Graph API or other APIs requiring delegated access
    from django_auth_adfs.utils import get_obo_access_token

These utility functions automatically handle decryption of the tokens, so you don't need to worry about the encryption details.

.. warning::
    You should always use these utility functions to access tokens rather than accessing them directly from the session.
    Direct access to ``request.session["ADFS_ACCESS_TOKEN"]`` will give you the encrypted token, not the actual token value.

Examples
----------------------

Here are practical examples of using these utility functions in your views:

Using with Microsoft Graph API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this flow, we will exchange our access token from the authentication process for an OBO token to access Microsoft Graph API.

This is the recommended flow for delegated access to Microsoft Graph API.

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    from django_auth_adfs.utils import get_obo_access_token
    import requests

    @login_required
    def me_view(request):
        """Get the user's profile from Microsoft Graph API"""
        obo_token = get_obo_access_token(request)

        if not obo_token:
            return JsonResponse({"error": "No OBO token available"}, status=401)

        headers = {
            "Authorization": f"Bearer {obo_token}",
            "Content-Type": "application/json",
        }

        try:
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)
            response.raise_for_status()
            return JsonResponse(response.json())
        except requests.exceptions.RequestException as e:
            return JsonResponse(
                {"error": "Failed to fetch user profile", "details": str(e)},
                status=500
            )

Using with other resources
~~~~~~~~~~~~~~~~~~~~~~~~~~

The key difference here is to use the ``get_access_token`` function to get the token for the resource you are accessing.

This is different than the ``get_obo_access_token`` function, which is used for Microsoft Graph API delegated access in the previous example.

.. code-block:: python

    from rest_framework.views import APIView
    from rest_framework.response import Response
    from django_auth_adfs.utils import get_access_token
    import requests

    class ExternalApiView(APIView):
        def get(self, request):
            """Call an API that accepts your application's token"""
            token = get_access_token(request)

            if not token:
                return Response({"error": "No access token available"}, status=401)

            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get("https://api.example.com/data", headers=headers)

            return Response(response.json())

Debug view
----------

The following example code demonstrates a debug view to check the values of the tokens stored in the session:

.. code-block:: python

    from django.contrib.auth.decorators import login_required
    from django.http import JsonResponse
    from django_auth_adfs.utils import get_access_token, get_obo_access_token
    from datetime import datetime

    @login_required
    def debug_view(request):
        """
        Debug view that provides detailed information about the authentication state,
        tokens, and session data.
        """
        if not request.user.is_authenticated:
            return JsonResponse({"authenticated": False})

        # Basic session token info
        session_info = {
            "has_access_token": "ADFS_ACCESS_TOKEN" in request.session,
            "has_refresh_token": "ADFS_REFRESH_TOKEN" in request.session,
            "has_expires_at": "ADFS_TOKEN_EXPIRES_AT" in request.session,
        }

        # Add token expiration details if available
        if "ADFS_TOKEN_EXPIRES_AT" in request.session:
            from datetime import datetime

            try:
                expires_at = datetime.fromisoformat(
                    request.session["ADFS_TOKEN_EXPIRES_AT"]
                )
                now = datetime.now()
                session_info["token_expires_at"] = expires_at.isoformat()
                session_info["expires_in_seconds"] = max(
                    0, int((expires_at - now).total_seconds())
                )
                session_info["is_expired"] = expires_at <= now
            except (ValueError, TypeError) as e:
                session_info["expiration_parse_error"] = str(e)

        # Show raw encrypted tokens for debugging
        if "ADFS_ACCESS_TOKEN" in request.session:
            raw_token = request.session["ADFS_ACCESS_TOKEN"]
            session_info["raw_token_preview"] = f"{raw_token[:10]}...{raw_token[-10:]}"
            session_info["raw_token_length"] = len(raw_token)

            # Try to decode as JWT without decryption (should fail if properly encrypted)
            try:
                import jwt

                jwt.decode(raw_token, options={"verify_signature": False})
                session_info["is_encrypted"] = False
            except:
                session_info["is_encrypted"] = True

        # Get properly decrypted access token
        try:
            from django_auth_adfs.utils import get_access_token

            access_token = get_access_token(request)
            session_info["decrypted_access_token_available"] = access_token is not None

            if access_token:
                if len(access_token) > 20:
                    session_info["decrypted_access_token_preview"] = (
                        f"{access_token[:10]}...{access_token[-10:]}"
                    )
                session_info["decrypted_access_token_length"] = len(access_token)

                # Try to decode as JWT (should succeed if properly decrypted)
                try:
                    import jwt

                    decoded = jwt.decode(access_token, options={"verify_signature": False})
                    session_info["jwt_decode_success"] = True
                    # Add some basic JWT info without exposing sensitive data
                    if "exp" in decoded:
                        from datetime import datetime

                        exp_time = datetime.fromtimestamp(decoded["exp"])
                        session_info["jwt_expiry"] = exp_time.isoformat()
                except Exception as e:
                    session_info["jwt_decode_error"] = str(e)
        except Exception as e:
            session_info["access_token_error"] = f"Error getting access token: {str(e)}"

        # Check if OBO token is available
        try:
            from django_auth_adfs.utils import get_obo_access_token

            obo_token = get_obo_access_token(request)
            obo_info = {
                "has_obo_token": obo_token is not None,
            }

            # Show raw encrypted OBO token if available
            if "ADFS_OBO_ACCESS_TOKEN" in request.session:
                raw_obo = request.session["ADFS_OBO_ACCESS_TOKEN"]
                obo_info["raw_obo_preview"] = f"{raw_obo[:10]}...{raw_obo[-10:]}"
                obo_info["raw_obo_length"] = len(raw_obo)

            if obo_token:
                if len(obo_token) > 20:
                    obo_info["obo_token_preview"] = f"{obo_token[:10]}...{obo_token[-10:]}"
                obo_info["obo_token_length"] = len(obo_token)

                # Try to decode as JWT (should succeed if properly decrypted)
                try:
                    import jwt

                    decoded = jwt.decode(obo_token, options={"verify_signature": False})
                    obo_info["jwt_decode_success"] = True
                    # Add some basic JWT info without exposing sensitive data
                    if "exp" in decoded:
                        from datetime import datetime

                        exp_time = datetime.fromtimestamp(decoded["exp"])
                        obo_info["jwt_expiry"] = exp_time.isoformat()
                except Exception as e:
                    obo_info["jwt_decode_error"] = str(e)
        except Exception as e:
            obo_info = {"error": f"Error getting OBO token: {str(e)}"}

        # Return all the collected information
        return JsonResponse(
            {
                "authenticated": True,
                "user": {
                    "id": request.user.id,
                    "username": request.user.username,
                    "email": request.user.email,
                    "is_staff": request.user.is_staff,
                    "is_superuser": request.user.is_superuser,
                },
                "session_tokens": session_info,
                "obo_token": obo_info,
            },
            json_dumps_params={"indent": 2},
        )

Understanding Access Tokens vs. OBO Tokens
------------------------------------------

It's important to understand the difference between regular access tokens and OBO (On-Behalf-Of) tokens, especially in the context of delegated access versus application access:

**Delegated Access vs. Application Access**:
    There are two primary ways an application can access resources in Azure AD/ADFS:

    * **Application Access**: The application accesses resources directly with its own identity, not on behalf of a user.

    * **Delegated Access**: The application accesses resources on behalf of a signed-in user.

**Regular Access Token**:
    The token obtained during authentication with ADFS.

**OBO (On-Behalf-Of) Token**:
    The OBO flow is specifically designed for delegated access scenarios where your application needs to access resources (like Microsoft Graph) on behalf of the authenticated user.

    The middleware handles this exchange automatically when OBO token storage is enabled.

For more information on the different types of permissions, see `the Microsoft documentation <https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview>`_.
