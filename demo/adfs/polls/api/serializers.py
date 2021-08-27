import rest_framework.serializers as serializers

from ..models import Choice, Question


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['id', 'question_text', 'pub_date']


class ChoiceSerializer(serializers.ModelSerializer):
    votes = serializers.IntegerField(read_only=True)

    class Meta:
        model = Choice
        fields = ['id', 'question', 'choice_text', 'votes']
