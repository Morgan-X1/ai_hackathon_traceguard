"""
URL configuration for Dashboard app
Includes RBAC-protected endpoints for data demasking and audit logs
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('batch-analysis/', views.batch_analysis, name='batch_analysis'),
    path('network-visualization/', views.network_visualization, name='network_visualization'),
    path('api/predict/', views.predict_api, name='predict_api'),
    path('api/demask/', views.demask_transaction, name='demask_transaction'),
    path('api/forensic-report/', views.generate_ai_forensic_report, name='forensic_report'),
    path('api/gemma-deep-analysis/', views.gemma_deep_analysis, name='gemma_deep_analysis'),
    path('api/test-gemma/', views.test_gemma_endpoint, name='test_gemma'),  # Test endpoint
    path('export-forensic-pdf/<str:case_id>/', views.export_forensic_pdf, name='export_forensic_pdf'),
    path('audit-log/', views.audit_log, name='audit_log'),
    path('about/', views.about, name='about'),
]
