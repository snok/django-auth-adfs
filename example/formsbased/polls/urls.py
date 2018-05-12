from django.urls import path

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('<int:pk>/', views.DetailView.as_view(), name='detail'),
    path('<int:pk>/vote/', views.VoteView.as_view(), name='vote'),
    # path('<int:pk>/savevote/', views.savevote, name='savevote'),
]
