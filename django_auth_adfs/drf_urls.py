"""
These URL patterns are used to override the default Django Rest Framework login page.

It's a bit of a hack, but DRF doesn't support overriding the login URL.
"""
from django.urls import re_path

from django_auth_adfs import views

app_name = "rest_framework"

urlpatterns = [
    re_path(r'^login$', views.OAuth2LoginView.as_view(), name='login'),
    re_path(r'^logout$', views.OAuth2LogoutView.as_view(), name='logout'),
]
