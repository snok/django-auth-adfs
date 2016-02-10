from django.conf import settings as django_settings


class Settings(object):
    def __init__(self):
        # TODO: Validate whether required settings are set
        self._defaults = {
            "ADFS_SERVER": None,  # Required
            "ADFS_AUTHORIZE_PATH": "/adfs/oauth2/authorize",
            "ADFS_TOKEN_PATH": "/adfs/oauth2/token",
            "ADFS_CLIENT_ID": None,  # Required
            "ADFS_RESOURCE": None,  # Required
            "ADFS_SIGNING_CERT": None,
            "ADFS_AUDIENCE": None,
            "ADFS_ISSUER": None,
            "ADFS_CA_BUNDLE": True,
            "ADFS_REDIR_URI": None,
            "ADFS_AFTER_LOGIN_URL": "/",
            "ADFS_USERNAME_CLAIM": "winaccountname",  # Required
            "ADFS_GROUP_CLAIM": "group",
            "ADFS_CLAIM_MAPPING": {},
            "REQUIRE_LOGIN_EXEMPT_URLS": [],
        }
        self._user_settings = getattr(django_settings, "AUTH_ADFS")

    def __getattr__(self, attr):
        if attr not in self._defaults:
            raise AttributeError("Invalid API setting: '%s'" % attr)

        try:
            val = self._user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self._defaults[attr]

        # Cache the result
        setattr(self, attr, val)
        return val


settings = Settings()
