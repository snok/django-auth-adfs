from django.http import HttpResponse
from django.views import View


def test_failed_response(request, error_message, status):
    pass


class TestView(View):
    def get(self, request):
        return HttpResponse('okay')
