from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured


class Settings(object):
    def __init__(self):
        # Set defaults
        self.ADFS_SERVER = None  # Required
        self.ADFS_AUTHORIZE_PATH = "/adfs/oauth2/authorize"
        self.ADFS_TOKEN_PATH = "/adfs/oauth2/token"
        self.ADFS_CLIENT_ID = None  # Required
        self.ADFS_RESOURCE = None  # Required
        self.ADFS_SIGNING_CERT = None  # Required
        self.ADFS_AUDIENCE = None
        self.ADFS_ISSUER = None
        self.ADFS_CA_BUNDLE = True
        self.ADFS_REDIR_URI = None  # Required
        self.ADFS_LOGIN_REDIRECT_URL = None
        self.ADFS_USERNAME_CLAIM = "winaccountname"
        self.ADFS_GROUP_CLAIM = "group"
        self.ADFS_CLAIM_MAPPING = {}
        self.REQUIRE_LOGIN_EXEMPT_URLS = []

        required_settings = [
            "ADFS_SERVER",
            "ADFS_CLIENT_ID",
            "ADFS_RESOURCE",
            "ADFS_SIGNING_CERT",
            "ADFS_REDIR_URI",
            "ADFS_USERNAME_CLAIM",
        ]

        if not hasattr(django_settings, "AUTH_ADFS"):
            msg = "The configuration directive 'AUTH_ADFS' was not found in your Django settings"
            raise ImproperlyConfigured(msg)

        # Overwrite defaults with user settings
        for setting in django_settings.AUTH_ADFS:
            if hasattr(self, setting):
                setattr(self, setting, django_settings.AUTH_ADFS[setting])
            else:
                msg = "'{0}' is not a valid configuration directive"
                raise ImproperlyConfigured(msg.format(setting))

        # Validate required settings
        for setting in required_settings:
            if not getattr(self, setting):
                msg = "ADFS setting '{0}' has not been set".format(setting)
                raise ImproperlyConfigured(msg)


settings = Settings()
