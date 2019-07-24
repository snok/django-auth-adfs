from django.conf.urls import url

from django_auth_adfs import views
from django_auth_adfs.rest_framework import views as drf_views


app_name = "django_auth_adfs"

urlpatterns = [
    url(r'^callback$', drf_views.OAuth2CallbackAPIView.as_view(), name='callback'),
    url(r'^login$', views.OAuth2LoginView.as_view(), name='login'),
    url(r'^login_no_sso$', views.OAuth2LoginNoSSOView.as_view(), name='login-no-sso'),
    url(r'^logout$', views.OAuth2LogoutView.as_view(), name='logout'),
    url(r'^refresh$', drf_views.OAuth2RefreshTokenAPIView.as_view(), name='refresh'),
]
