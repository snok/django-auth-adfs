from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^login$', views.OAuth2View.as_view(), name='login'),
    url(r'^adfs$', views.LoginView.as_view(), name='adfs'),
]
