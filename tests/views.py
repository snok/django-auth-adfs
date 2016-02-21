from django.shortcuts import render


def context_processor(request):
    return render(request, 'context_processor/context_processor.html')
