from ..models import Choice, Question
import rest_framework.serializers as serializers


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['id', 'question_text', 'pub_date']


class ChoiceSerializer(serializers.ModelSerializer):
    votes = serializers.IntegerField(read_only=True)

    class Meta:
        model = Choice
        fields = ['id', 'question', 'choice_text', 'votes']
