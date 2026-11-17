from django.urls import path
from . import views

app_name = 'dashboard'
urlpatterns = [
    path('', views.index, name='index'),

    path('dashboard/', views.dashboard, name='dashboard'),

    # path('password/', views.password, name='password'),

    # path('file_hash/', views.file_hash, name='file_hash'),

    # path('file_metadata/', views.file_metadata, name='file_metadata'),

    # path('qr_code/', views.qr_code, name='qr_code')

]