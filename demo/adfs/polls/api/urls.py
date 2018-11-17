from rest_framework import routers

from . import views


router = routers.DefaultRouter()

router.register(r'questions', views.QuestionViewSet)
router.register(r'choices', views.ChoiceViewSet)

app_name = 'polls-api'
urlpatterns = router.urls
