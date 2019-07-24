from django.conf.urls import url, include

urlpatterns = [
    url(r'^api/oauth2/', include('django_auth_adfs.rest_urls')),
]
