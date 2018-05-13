"""
Based on https://djangosnippets.org/snippets/1179/
"""
import django
from django.conf import settings as django_settings
from django.http import HttpResponseRedirect
from re import compile

from django_auth_adfs.config import settings
from django_auth_adfs.util import get_adfs_auth_url

try:
    from django.urls import reverse
except ImportError:  # Django < 1.10
    from django.core.urlresolvers import reverse

try:
    from django.utils.deprecation import MiddlewareMixin
except ImportError:  # Django < 1.10
    MiddlewareMixin = object

LOGIN_EXEMPT_URLS = [
    compile(django_settings.LOGIN_URL.lstrip('/')),
    compile(reverse("django_auth_adfs:login").lstrip('/')),
]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    LOGIN_EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


class LoginRequiredMiddleware(MiddlewareMixin):
    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """
    def process_request(self, request):
        assert hasattr(request, 'user'), "The Login Required middleware requires" \
                                         " authentication middleware to be installed." \
                                         " Edit your MIDDLEWARE setting to insert" \
                                         " 'django.contrib.auth.middlware.AuthenticationMiddleware'." \
                                         " If that doesn't work, ensure your TEMPLATE_CONTEXT_PROCESSORS" \
                                         " setting includes 'django.core.context_processors.auth'."

        if django.VERSION[:2] < (1, 10):
            user_authenticated = request.user.is_authenticated()
        else:
            user_authenticated = request.user.is_authenticated

        if not user_authenticated:
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in LOGIN_EXEMPT_URLS):
                return HttpResponseRedirect(get_adfs_auth_url(hostname=request.get_host()))
