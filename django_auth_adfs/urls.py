from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^login$', views.OAuth2View.as_view(), name='login'),
]
