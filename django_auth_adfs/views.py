import django
from django.conf import settings as django_settings
from django.contrib.auth import authenticate, login
from django.http.response import HttpResponse
from django.shortcuts import redirect
from django.views.generic import View
from django.utils.http import is_safe_url, urlsafe_base64_decode

from django_auth_adfs.config import settings


class OAuth2View(View):
    def get(self, request):
        """
        Handles the redirect from ADFS to our site.
        We try to process the passed authorization code and login the user.

        Args:
            request (django.http.request.HttpRequest): A Django Request object
        """
        code = request.GET.get("code", None)

        user = authenticate(request=request, authorization_code=code)

        if user is not None:
            if user.is_active:
                login(request, user)

                if request.GET.get('state'):  # currently this is only the "next" URL
                    next_url = urlsafe_base64_decode(request.GET.get('state')).decode()
                    if django.VERSION < (1, 11):
                        hosts_arg = {'host': request.get_host()}
                    else:
                        hosts_arg = {
                            'allowed_hosts': {request.get_host()},
                            'require_https': request.is_secure()
                        }

                    if is_safe_url(
                        url=next_url,
                        **hosts_arg
                    ):
                        return redirect(next_url)

                # Redirect to the "after login" page.
                if settings.LOGIN_REDIRECT_URL:
                    return redirect(settings.LOGIN_REDIRECT_URL)

                return redirect(django_settings.LOGIN_REDIRECT_URL)
            else:
                # Return a 'disabled account' error message
                return HttpResponse("Account disabled", status=403)
        else:
            # Return an 'invalid login' error message
            return HttpResponse("Login failed", status=401)
