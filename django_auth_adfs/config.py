from django.conf import settings as django_settings
from django.core.exceptions import ImproperlyConfigured


class Settings(object):
    def __init__(self):
        # Set defaults
        self.SERVER = None  # Required
        self.AUTHORIZE_PATH = "/adfs/oauth2/authorize"
        self.TOKEN_PATH = "/adfs/oauth2/token"
        self.CLIENT_ID = None  # Required
        self.RESOURCE = None  # Required
        self.SIGNING_CERT = True  # Autoload by default
        self.CERT_MAX_AGE = 24  # hours
        self.AUDIENCE = None
        self.ISSUER = None
        self.CA_BUNDLE = True
        self.REDIR_URI = None  # Required
        self.LOGIN_REDIRECT_URL = None
        self.USERNAME_CLAIM = "winaccountname"
        self.GROUP_CLAIM = "group"
        self.CLAIM_MAPPING = {}
        self.BOOLEAN_CLAIM_MAPPING = {}
        self.LOGIN_EXEMPT_URLS = []
        self.REDIRECT_FIELD_NAME = 'next'  # same as django auth

        required_settings = [
            "SERVER",
            "CLIENT_ID",
            "RESOURCE",
            "REDIR_URI",
            "USERNAME_CLAIM",
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
