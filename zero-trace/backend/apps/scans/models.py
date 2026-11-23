"""Scan, finding, authorization and recommendation models.

Privacy rule: raw detected values are never persisted. Only redacted evidence
and one-way fingerprints are stored so the UI can show *where* something was
found without revealing *what* it was.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class Severity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Info"


class ScanType(models.TextChoices):
    DOCUMENT = "document", "Document"
    REPOSITORY = "repository", "Repository"


class ScanStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"


class FindingCategory(models.TextChoices):
    EMAIL = "email", "Email address"
    PHONE = "phone", "Phone number"
    API_KEY = "api_key", "API key / token"
    CREDENTIAL = "credential", "Hardcoded credential"
    METADATA = "metadata", "Sensitive metadata"
    PII = "pii", "Personally identifiable information"
    CONFIDENTIAL = "confidential", "Confidential information"
    FINANCIAL = "financial", "Financial identifier"
    CONFIG = "config", "Exposed configuration secret"


class AuditEvent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="audit_events")
    action = models.CharField(max_length=80)
    target = models.CharField(max_length=255, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "created_at"])]

    def __str__(self) -> str:
        return f"{self.action}:{self.target or self.user.email}"


class RepositoryAuthorization(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="repository_authorizations")
    repository = models.CharField(max_length=255, help_text="owner/repo")
    token_fingerprint = models.CharField(max_length=64, help_text="SHA-256 fingerprint of the supplied token; the token itself is never stored.")
    scopes = models.CharField(max_length=255, blank=True)
    authorized_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "repository"], name="unique_user_repository_authorization"),
        ]
        ordering = ["-authorized_at"]

    def __str__(self) -> str:
        return f"{self.repository} ({self.user.email})"


class Scan(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans")
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    status = models.CharField(max_length=20, choices=ScanStatus.choices, default=ScanStatus.QUEUED)
    source_name = models.CharField(max_length=255)
    source_hash = models.CharField(max_length=64, blank=True)
    mime_type = models.CharField(max_length=120, blank=True)
    size_bytes = models.PositiveBigIntegerField(default=0)
    metadata = models.JSONField(default=dict, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_level = models.CharField(max_length=20, default="low")
    ai_summary = models.TextField(blank=True)
    ai_used = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    authorization = models.ForeignKey(
        RepositoryAuthorization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scans",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["user", "risk_level"]),
        ]

    def __str__(self) -> str:
        return f"{self.scan_type}:{self.source_name}"


class Finding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=30, choices=FindingCategory.choices)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    title = models.CharField(max_length=255)
    redacted_evidence = models.CharField(max_length=500)
    redacted_context = models.CharField(max_length=400, blank=True)
    fingerprint = models.CharField(max_length=64)
    location = models.CharField(max_length=500, blank=True)
    explanation = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    confidence = models.FloatField(default=1.0)
    source_tool = models.CharField(max_length=50, default="regex")
    false_positive = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-severity", "category"]
        constraints = [
            models.UniqueConstraint(fields=["scan", "fingerprint"], name="unique_finding_per_scan"),
        ]
        indexes = [
            models.Index(fields=["scan", "severity"]),
            models.Index(fields=["scan", "category"]),
        ]

    def __str__(self) -> str:
        return f"{self.severity}:{self.title}"


class Recommendation(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="recommendations")
    title = models.CharField(max_length=255)
    description = models.TextField()
    priority = models.PositiveSmallIntegerField(default=1)
    category = models.CharField(max_length=30, blank=True)
    action_key = models.CharField(max_length=80, blank=True)

    class Meta:
        ordering = ["priority", "id"]

    def __str__(self) -> str:
        return self.title
