"""API serializers. All sensitive values are redacted before serialisation."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from apps.engine.redaction import redact_label
from apps.scans.models import AuditEvent, Finding, Recommendation, Scan

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password")
        extra_kwargs = {"username": {"required": True}}

    def validate_email(self, value: str) -> str:
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value.casefold()

    def create(self, validated_data: dict) -> User:
        return User.objects.create_user(**validated_data)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "email", "ai_consent", "ai_consent_at", "date_joined")
        read_only_fields = ("id", "email", "date_joined", "ai_consent_at")


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ConsentSerializer(serializers.Serializer):
    ai_consent = serializers.BooleanField()


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = (
            "id", "category", "severity", "title", "redacted_evidence", "redacted_context",
            "location", "explanation", "remediation", "confidence", "source_tool",
            "false_positive", "created_at",
        )
        read_only_fields = fields


class RecommendationSerializer(serializers.ModelSerializer):
    scan_id = serializers.UUIDField(read_only=True)
    source_name = serializers.SerializerMethodField()

    class Meta:
        model = Recommendation
        fields = ("id", "scan_id", "source_name", "title", "description", "priority", "category", "action_key")
        read_only_fields = fields

    def get_source_name(self, obj: Recommendation) -> str:
        return redact_label(obj.scan.source_name)


class ScanListSerializer(serializers.ModelSerializer):
    source_name = serializers.SerializerMethodField()
    finding_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Scan
        fields = (
            "id", "scan_type", "status", "source_name", "risk_score", "risk_level",
            "summary", "finding_count", "created_at", "completed_at", "error_message",
        )
        read_only_fields = fields

    def get_source_name(self, obj: Scan) -> str:
        return redact_label(obj.source_name)


class ScanDetailSerializer(serializers.ModelSerializer):
    source_name = serializers.SerializerMethodField()
    findings = FindingSerializer(many=True, read_only=True)
    recommendations = RecommendationSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = (
            "id", "scan_type", "status", "source_name", "risk_score", "risk_level",
            "metadata", "summary", "ai_summary", "ai_used", "error_message",
            "created_at", "started_at", "completed_at", "findings", "recommendations",
        )
        read_only_fields = fields

    def get_source_name(self, obj: Scan) -> str:
        return redact_label(obj.source_name)


class DocumentScanRequestSerializer(serializers.Serializer):
    file = serializers.FileField()


class BatchDocumentScanRequestSerializer(serializers.Serializer):
    files = serializers.ListField(child=serializers.FileField(), allow_empty=False, max_length=10)


class SanitizeRequestSerializer(serializers.Serializer):
    file = serializers.FileField()


class FalsePositiveSerializer(serializers.Serializer):
    false_positive = serializers.BooleanField()


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = ("id", "action", "target", "metadata", "created_at")
        read_only_fields = fields


class RepositoryScanRequestSerializer(serializers.Serializer):
    repository = serializers.RegexField(r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$", max_length=255)
    token = serializers.CharField(write_only=True, trim_whitespace=True, min_length=10, max_length=255)
    authorize = serializers.BooleanField()

    def validate_authorize(self, value: bool) -> bool:
        if value is not True:
            raise serializers.ValidationError("Explicit authorization is required before scanning any repository.")
        return value
