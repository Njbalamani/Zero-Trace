"""API URL routes."""

from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.HealthView.as_view(), name="health"),
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("auth/me/", views.MeView.as_view(), name="me"),
    path("auth/consent/", views.ConsentView.as_view(), name="consent"),
    path("scans/documents/", views.DocumentScanView.as_view(), name="document-scan"),
    path("scans/documents/batch/", views.BatchDocumentScanView.as_view(), name="batch-document-scan"),
    path("scans/repositories/", views.RepositoryScanView.as_view(), name="repository-scan"),
    path("scans/", views.ScanListView.as_view(), name="scan-list"),
    path("scans/<uuid:pk>/", views.ScanDetailView.as_view(), name="scan-detail"),
    path("scans/<uuid:pk>/report/", views.ScanReportView.as_view(), name="scan-report"),
    path("tools/sanitize/", views.SanitizeDocumentView.as_view(), name="sanitize-document"),
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    path("recommendations/", views.RecommendationListView.as_view(), name="recommendations"),
    path("findings/", views.FindingsView.as_view(), name="findings"),
    path("findings/<int:pk>/review/", views.FindingFalsePositiveView.as_view(), name="finding-review"),
    path("audit/", views.AuditEventListView.as_view(), name="audit"),
]
