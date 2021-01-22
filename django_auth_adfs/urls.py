from django.conf.urls import re_path

from django_auth_adfs import views

app_name = "django_auth_adfs"

urlpatterns = [
    re_path(r'^callback$', views.OAuth2CallbackView.as_view(), name='callback'),
    re_path(r'^login$', views.OAuth2LoginView.as_view(), name='login'),
    re_path(r'^login_no_sso$', views.OAuth2LoginNoSSOView.as_view(), name='login-no-sso'),
    re_path(r'^login_force_mfa$', views.OAuth2LoginForceMFA.as_view(), name='login-force-mfa'),
    re_path(r'^logout$', views.OAuth2LogoutView.as_view(), name='logout'),
]
