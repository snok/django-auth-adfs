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

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    'django_auth_adfs.middleware.LoginRequiredMiddleware',
)
# Django < 1.10 compatibility
MIDDLEWARE_CLASSES = MIDDLEWARE

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
    "CLIENT_ID": "your-configured-client-id",
    "RELYING_PARTY_ID": "your-adfs-RPT-name",
    "AUDIENCE": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
    "CA_BUNDLE": "/path/to/ca-bundle.pem",
    "CLAIM_MAPPING": {"first_name": "given_name",
                      "last_name": "family_name",
                      "email": "email"},
    "BOOLEAN_CLAIM_MAPPING": {"is_staff": "user_is_staff",
                              "is_superuser": "user_is_superuser"},
    "LOGIN_EXEMPT_URLS": ["^context_processor/$"]
}
