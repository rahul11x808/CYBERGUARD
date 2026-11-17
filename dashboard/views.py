from django.shortcuts import render
from django.http import Http404

# Create your views here.
from django.http import HttpResponse

def index(request):
    return render(request, 'dashboard/index.html')

def dashboard(request):
    return render(request, 'dashboard/dashboard.html')

# def password(request):
#     return render(request, 'dashboard/password.html')    

# def file_hash(request):
#     return render(request, 'dashboard/file_hash.html')

# def file_metadata(request):
#     return render(request, 'dashboard/file_metadata.html')

# def qr_code(request):
#     return render(request, 'dashboard/qrcode.html')