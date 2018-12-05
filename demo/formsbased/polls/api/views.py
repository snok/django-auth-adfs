from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..models import Question, Choice
from .serializers import QuestionSerializer, ChoiceSerializer
from .filters import QuestionFilter, ChoiceFilter


class QuestionViewSet(ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer
    filter_class = QuestionFilter


class ChoiceViewSet(ModelViewSet):
    queryset = Choice.objects.all()
    serializer_class = ChoiceSerializer
    filter_class = ChoiceFilter

    @action(methods=["post"], detail=True, permission_classes=[IsAuthenticated])
    def vote(self, request, pk=None):
        """
        post:
        A description of the post method on the custom action.
        """
        choice = self.get_object()
        choice.vote()
        serializer = self.get_serializer(choice)
        return Response(serializer.data)
