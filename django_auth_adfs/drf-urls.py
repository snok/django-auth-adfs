"""
These URL patterns are used to override the default Django Rest Framework login page.

It's a bit of a hack, but DRF doesn't support overriding the login URL.
"""
from django.conf.urls import url

from django_auth_adfs import views

app_name = "rest_framework"

urlpatterns = [
    url(r'^login$', views.OAuth2LoginView.as_view(), name='login'),
]
