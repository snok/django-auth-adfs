from django.contrib.auth import authenticate, login
from django.core.urlresolvers import reverse
from django.http.response import HttpResponse
from django.shortcuts import redirect
from django.views.generic import View

from django_auth_adfs.config import Settings


class OAuth2View(View):
    def get(self, request):
        code = request.GET["code"]

        redir_uri = "{0}://{1}{2}".format(request.scheme, request.META['HTTP_HOST'], reverse("auth_adfs:login"))
        user = authenticate(authorization_code=code, redir_uri=redir_uri)

        if user is not None:
            if user.is_active:
                login(request, user)
                settings = Settings()
                # Redirect to a success page.
                return redirect(settings.ADFS_AFTER_LOGIN_URL)
            else:
                # Return a 'disabled account' error message
                return HttpResponse("Login failed")
        else:
            # Return an 'invalid login' error message.
            return HttpResponse("Login failed")
