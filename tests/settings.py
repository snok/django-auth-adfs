SECRET_KEY = 'secret'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
    }
}

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',

                'django_auth_adfs.context_processors.adfs_url',
            ],
        },
        'DIRS': 'templates'
    },
]

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    'django_auth_adfs.middleware.LoginRequiredMiddleware',
)

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'django_auth_adfs',
    'tests',
)

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    'django_auth_adfs.backend.AdfsBackend',
)

ROOT_URLCONF = 'tests.urls'

STATIC_ROOT = '/tmp/'  # Dummy
STATIC_URL = '/static/'

AUTH_ADFS = {
    "SERVER": "adfs.example.com",
    "REDIR_URI": "example.com",
    "CLIENT_ID": "your-configured-client-id",
    "RESOURCE": "your-adfs-RPT-name",
    "SIGNING_CERT": """
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIJALLjs7wGmYSvMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV
BAMMEGFkZnMuZXhhbXBsZS5jb20wHhcNMTYwMjE1MjAyNDQxWhcNMjYwMjEyMjAy
NDQxWjAbMRkwFwYDVQQDDBBhZGZzLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAy3JZC0ZF+8XpDQxQQDZEtmThOLnhld1TlLTBSEX7
lLLoDvlTVfop3LgWhdGhW1gM3Wa47oR3ni3JoXrbky+cAkMkslzu+p4xMS1ApZAp
ZUFh9ZL9eEXrvqZLYG0N20ffHkKd8XVN4w5nYQWHxp2uSECrStVAnL2m6DH1/Tla
DQAmrmaye+djXAxZjR6m/SQxQXOn6tLL9BMEF/UVt8GocSuATJdrXaKg9ubwR3j7
GRfRNNy1v+5LYfcRVFrFmupbL/6k8fUHeQ1qKNAhAvpcZl+4df1phUZJMnwcQncX
I3zqypz8bTTjTvu//iKr2U7Ih3TJdf/F51lPF0JaVB30jQIDAQABo1AwTjAdBgNV
HQ4EFgQUkbP4sH/t1YR+8DLC1+xHyAYEohQwHwYDVR0jBBgwFoAUkbP4sH/t1YR+
8DLC1+xHyAYEohQwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAuMkH
KIurKQsktlaOebbPnpz1iqKUoSM8Vvf6TqX4hf1gIxoQJfVUdoktNCwHt+n/Fzvt
gzuHbigBdHKVQx7wlPc4dBRNmfqtOwpgtdrXq9suDjiPZHsEhui9Ak4ufXxzSUzx
KBc7RO0FWqgEMNVc5pKAWV9SN5e6nuH0uJnfj3f1EgVN8ia1TXkZiOOUMPpPOToJ
kyXR6FepOSOQRXPUoN2wozj4KbJBtpKQk0niMf5rPzN1hsNokt2HtVlcnZ25NV42
SEtFTMAxlamUZ0PhC2H9nxDo3dN8KS44fT4hBx5FUaUffetl4Q5ebrJ1IoBNZ6+S
aK7TCdKeEyDaHh6/Dg==
-----END CERTIFICATE-----
""",
    "AUDIENCE": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
    "ISSUER": "http://adfs.example.com/adfs/services/trust",
    "CA_BUNDLE": "/path/to/ca-bundle.pem",
    "CLAIM_MAPPING": {"first_name": "given_name",
                      "last_name": "family_name",
                      "email": "email"},
    "LOGIN_EXEMPT_URLS": ["^context_processor/$"]
}
