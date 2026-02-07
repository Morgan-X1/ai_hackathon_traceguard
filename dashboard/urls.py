"""
URL configuration for Dashboard app
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('batch-analysis/', views.batch_analysis, name='batch_analysis'),
    path('api/predict/', views.predict_api, name='predict_api'),
    path('about/', views.about, name='about'),
]
