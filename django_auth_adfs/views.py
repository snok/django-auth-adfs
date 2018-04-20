from django.conf import settings as django_settings
from django.contrib.auth import authenticate, login
from django.http.response import HttpResponse
from django.shortcuts import redirect
from django.views.generic import View

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
                if request.GET.get(settings.REDIRECT_FIELD_NAME):
                    return redirect(request.GET.get(settings.REDIRECT_FIELD_NAME))
                # Redirect to the "after login" page.
                elif settings.LOGIN_REDIRECT_URL:
                    return redirect(settings.LOGIN_REDIRECT_URL)
                else:
                    return redirect(django_settings.LOGIN_REDIRECT_URL)
            else:
                # Return a 'disabled account' error message
                return HttpResponse("Account disabled", status=403)
        else:
            # Return an 'invalid login' error message
            return HttpResponse("Login failed", status=401)
