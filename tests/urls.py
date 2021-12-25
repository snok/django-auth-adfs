from django.urls import include, re_path

urlpatterns = [
    re_path(r'^oauth2/', include('django_auth_adfs.urls')),
    re_path(r'^oauth2/', include('django_auth_adfs.drf_urls')),
]
