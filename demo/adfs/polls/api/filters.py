import django_filters
from ..models import Choice, Question


class QuestionFilter(django_filters.FilterSet):
    class Meta:
        model = Question
        fields = ['question_text', 'pub_date']


class ChoiceFilter(django_filters.FilterSet):
    class Meta:
        model = Choice
        fields = ['question', 'choice_text', 'votes']
