from django.shortcuts import render
from django.http import Http404

# Create your views here.
from django.http import HttpResponse

def index(request):
    # return HttpResponse("Hello, world. You're at the dashboard index.")
    return render(request, 'dashboard/index.html')
def dashboard(request):
    return render(request, 'dashboard/dashboard.html')