"""REST API views for ZeroTrace."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import timedelta
from io import BytesIO

from django.contrib.auth import authenticate, get_user_model
from django.db import transaction
from django.db.models import Count
from django.http import FileResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.engine import document_scanner, gitleaks_runner, github_scanner, nlp_detector, report_generator, risk_engine, sanitizer
from apps.engine.redaction import redact_label
from apps.scans.audit import log_event
from apps.scans.models import AuditEvent, Finding, Recommendation, RepositoryAuthorization, Scan, ScanStatus

from .serializers import (
    AuditEventSerializer,
    BatchDocumentScanRequestSerializer,
    ConsentSerializer,
    DocumentScanRequestSerializer,
    FalsePositiveSerializer,
    FindingSerializer,
    LoginSerializer,
    RecommendationSerializer,
    RegisterSerializer,
    RepositoryScanRequestSerializer,
    SanitizeRequestSerializer,
    ScanDetailSerializer,
    ScanListSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)
User = get_user_model()

FINDING_FIELDS = {
    "category", "severity", "title", "redacted_evidence", "redacted_context", "fingerprint",
    "location", "explanation", "remediation", "confidence", "source_tool",
}


def _persist_results(scan: Scan, result: dict, ai_summary: str, ai_used: bool) -> None:
    summary = risk_engine.calculate_risk(result["findings"])
    recommendations = risk_engine.build_recommendations(result["findings"])
    with transaction.atomic():
        scan.source_hash = result.get("source_hash", "")[:64]
        scan.mime_type = result.get("mime_type", "")[:120]
        scan.size_bytes = result.get("size_bytes", 0)
        scan.metadata = result.get("metadata", {})
        scan.summary = summary
        scan.risk_score = summary["score"]
        scan.risk_level = summary["level"]
        scan.ai_summary = ai_summary
        scan.ai_used = ai_used
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = timezone.now()
        scan.error_message = ""
        scan.save()

        Finding.objects.bulk_create(
            [
                Finding(scan=scan, **{key: value for key, value in item.items() if key in FINDING_FIELDS})
                for item in result["findings"]
            ],
            ignore_conflicts=True,
        )
        Recommendation.objects.bulk_create(
            [Recommendation(scan=scan, **item) for item in recommendations]
        )


def _fail_scan(scan: Scan, message: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error_message = message[:1000]
    scan.completed_at = timezone.now()
    scan.save(update_fields=["status", "error_message", "completed_at"])


def _scan_one_document(user, uploaded):
    data = uploaded.read()
    source_label = redact_label(uploaded.name)[:255]
    scan = Scan.objects.create(
        user=user,
        scan_type="document",
        status=ScanStatus.RUNNING,
        source_name=source_label,
        mime_type=(uploaded.content_type or "")[:120],
        size_bytes=len(data),
        started_at=timezone.now(),
    )
    try:
        result = document_scanner.scan_document(uploaded.name, data)
        preview = risk_engine.calculate_risk(result["findings"])
        ai_summary, ai_used = risk_engine.ai_assessment(preview, result["findings"], user.ai_consent)
        _persist_results(scan, result, ai_summary, ai_used)
        log_event(user, "document_scan", source_label, {"findings": len(result["findings"]), "risk": scan.risk_score})
        return scan, "", None
    except ValueError as exc:
        _fail_scan(scan, str(exc))
        log_event(user, "document_scan_failed", source_label, {})
        return scan, str(exc), status.HTTP_400_BAD_REQUEST
    except Exception:
        logger.exception("Document scan failed")
        message = "Internal scanning error. No file contents were stored."
        _fail_scan(scan, message)
        log_event(user, "document_scan_failed", source_label, {})
        return scan, message, status.HTTP_500_INTERNAL_SERVER_ERROR
    finally:
        data = b""


class HealthView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(
            {
                "status": "ok",
                "service": "ZeroTrace Privacy Analyzer",
                "detectors": nlp_detector.detector_status(),
                "gitleaks_available": gitleaks_runner.gitleaks_available(),
                "files_supported": [".pdf", ".docx"],
                "external_ai": "opt-in only",
            }
        )


class RegisterView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user": UserSerializer(user).data}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"].casefold()
        user = authenticate(request, username=email, password=serializer.validated_data["password"])
        if user is None or not user.is_active:
            return Response({"detail": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
        token, _ = Token.objects.get_or_create(user=user)
        log_event(user, "login", user.email, {})
        return Response({"token": token.key, "user": UserSerializer(user).data})


class LogoutView(APIView):
    def post(self, request):
        token = getattr(request.user, "auth_token", None)
        if token:
            token.delete()
        return Response({"detail": "Signed out."})


class MeView(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)


class ConsentView(APIView):
    def post(self, request):
        serializer = ConsentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        consent = serializer.validated_data["ai_consent"]
        request.user.ai_consent = consent
        request.user.ai_consent_at = timezone.now() if consent else None
        request.user.save(update_fields=["ai_consent", "ai_consent_at"])
        log_event(request.user, "ai_consent_changed", "", {"enabled": consent})
        return Response(UserSerializer(request.user).data)


class DocumentScanView(APIView):
    def post(self, request):
        serializer = DocumentScanRequestSerializer(data=request.FILES)
        serializer.is_valid(raise_exception=True)
        scan, message, error_status = _scan_one_document(request.user, serializer.validated_data["file"])
        if error_status:
            return Response({"detail": message}, status=error_status)
        return Response(ScanDetailSerializer(scan).data, status=status.HTTP_201_CREATED)


class BatchDocumentScanView(APIView):
    def post(self, request):
        serializer = BatchDocumentScanRequestSerializer(data={"files": request.FILES.getlist("files")})
        serializer.is_valid(raise_exception=True)
        completed = []
        failed = []
        for uploaded in serializer.validated_data["files"]:
            scan, message, _ = _scan_one_document(request.user, uploaded)
            if scan.status == ScanStatus.COMPLETED:
                completed.append(ScanDetailSerializer(scan).data)
            else:
                failed.append({"source_name": redact_label(uploaded.name), "error": message})
        log_event(request.user, "batch_document_scan", "", {"completed": len(completed), "failed": len(failed)})
        return Response({"completed": completed, "failed": failed}, status=status.HTTP_201_CREATED)


class SanitizeDocumentView(APIView):
    def post(self, request):
        serializer = SanitizeRequestSerializer(data=request.FILES)
        serializer.is_valid(raise_exception=True)
        uploaded = serializer.validated_data["file"]
        data = uploaded.read()
        try:
            cleaned, output_name, mime_type = sanitizer.sanitize_document(uploaded.name, data)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Document sanitization failed")
            return Response({"detail": "Unable to sanitize this file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            data = b""

        safe_name = redact_label(output_name).replace('"', "")
        log_event(request.user, "document_sanitized", safe_name, {})
        response = FileResponse(BytesIO(cleaned), content_type=mime_type)
        response["Content-Disposition"] = f'attachment; filename="{safe_name}"'
        return response


class RepositoryScanView(APIView):
    def post(self, request):
        serializer = RepositoryScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data["token"]
        repository = serializer.validated_data["repository"]

        try:
            fingerprint = github_scanner.validate_token(token)
        except github_scanner.GitHubScanError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        authorization, _ = RepositoryAuthorization.objects.update_or_create(
            user=request.user,
            repository=repository,
            defaults={
                "token_fingerprint": fingerprint,
                "is_active": True,
                "expires_at": None,
            },
        )
        scan = Scan.objects.create(
            user=request.user,
            scan_type="repository",
            status=ScanStatus.RUNNING,
            source_name=repository,
            authorization=authorization,
            started_at=timezone.now(),
        )
        try:
            result = github_scanner.scan_repository(token, repository)
            preview = risk_engine.calculate_risk(result["findings"])
            ai_summary, ai_used = risk_engine.ai_assessment(preview, result["findings"], request.user.ai_consent)
            _persist_results(scan, result, ai_summary, ai_used)
            authorization.last_scanned_at = timezone.now()
            authorization.save(update_fields=["last_scanned_at"])
            log_event(request.user, "repository_scan", repository, {"findings": len(result["findings"]), "risk": scan.risk_score})
        except github_scanner.GitHubScanError as exc:
            _fail_scan(scan, str(exc))
            log_event(request.user, "repository_scan_failed", repository, {})
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            logger.exception("Repository scan failed")
            _fail_scan(scan, "Repository scanning error.")
            log_event(request.user, "repository_scan_failed", repository, {})
            return Response({"detail": "Repository scanning error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            token = ""

        return Response(ScanDetailSerializer(scan).data, status=status.HTTP_201_CREATED)


class ScanListView(APIView):
    def get(self, request):
        queryset = Scan.objects.filter(user=request.user).annotate(finding_count=Count("findings", distinct=True))
        scan_type = request.query_params.get("scan_type")
        if scan_type in {"document", "repository"}:
            queryset = queryset.filter(scan_type=scan_type)
        try:
            limit = min(max(int(request.query_params.get("limit", 50)), 1), 200)
        except ValueError:
            limit = 50
        return Response(ScanListSerializer(queryset[:limit], many=True).data)


class ScanDetailView(APIView):
    def get(self, request, pk):
        try:
            scan = Scan.objects.get(pk=pk, user=request.user)
        except (Scan.DoesNotExist, ValueError):
            return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(ScanDetailSerializer(scan).data)


class FindingFalsePositiveView(APIView):
    def post(self, request, pk):
        serializer = FalsePositiveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            finding = Finding.objects.select_related("scan").get(pk=pk, scan__user=request.user)
        except (Finding.DoesNotExist, ValueError):
            return Response({"detail": "Finding not found."}, status=status.HTTP_404_NOT_FOUND)

        finding.false_positive = serializer.validated_data["false_positive"]
        finding.save(update_fields=["false_positive"])
        scan = finding.scan
        active_findings = list(scan.findings.filter(false_positive=False).values("severity", "category"))
        summary = risk_engine.calculate_risk(active_findings)
        scan.summary = summary
        scan.risk_score = summary["score"]
        scan.risk_level = summary["level"]
        scan.save(update_fields=["summary", "risk_score", "risk_level"])
        log_event(
            request.user,
            "finding_reviewed",
            str(finding.id),
            {"false_positive": finding.false_positive, "scan_id": str(scan.id)},
        )
        return Response(ScanDetailSerializer(scan).data)


class AuditEventListView(APIView):
    def get(self, request):
        queryset = AuditEvent.objects.filter(user=request.user)[:100]
        return Response(AuditEventSerializer(queryset, many=True).data)


class ScanReportView(APIView):
    def get(self, request, pk):
        try:
            scan = Scan.objects.get(pk=pk, user=request.user)
        except (Scan.DoesNotExist, ValueError):
            return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
        pdf = report_generator.generate_report(scan, scan.findings.all(), scan.recommendations.all())
        response = FileResponse(BytesIO(pdf), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="zerotrace-report-{scan.id}.pdf"'
        return response


class DashboardView(APIView):
    def get(self, request):
        scans = Scan.objects.filter(user=request.user)
        completed = scans.filter(status=ScanStatus.COMPLETED)
        findings = Finding.objects.filter(scan__user=request.user, false_positive=False)

        severity_counts = Counter(findings.values_list("severity", flat=True))
        category_counts = Counter(findings.values_list("category", flat=True))
        risk_counts = Counter(completed.values_list("risk_level", flat=True))

        recent = list(completed.order_by("-created_at")[:8])
        trend = Counter()
        today = timezone.now().date()
        for days_ago in range(6, -1, -1):
            trend[str(today - timedelta(days=days_ago))] = 0
        for created_at in completed.filter(created_at__date__gte=today - timedelta(days=6)).values_list("created_at", flat=True):
            key = str(created_at.date())
            trend[key] += 1

        risk_items = list(completed.order_by("-created_at").values("created_at", "risk_score", "risk_level")[:12])
        risk_timeline = [
            {"date": item["created_at"].isoformat(), "score": item["risk_score"], "level": item["risk_level"]}
            for item in reversed(risk_items)
        ]

        ordered_scores = list(completed.order_by("created_at").values_list("risk_score", flat=True))
        improvement = 0.0
        if len(ordered_scores) >= 2:
            half = len(ordered_scores) // 2
            earlier = sum(ordered_scores[:half]) / half
            later = sum(ordered_scores[half:]) / (len(ordered_scores) - half)
            if earlier > 0:
                improvement = round(((earlier - later) / earlier) * 100, 1)

        return Response(
            {
                "totals": {
                    "scans": scans.count(),
                    "documents": scans.filter(scan_type="document").count(),
                    "repositories": scans.filter(scan_type="repository").count(),
                    "completed": completed.count(),
                    "failed": scans.filter(status=ScanStatus.FAILED).count(),
                    "findings": findings.count(),
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                },
                "risk_distribution": dict(risk_counts),
                "severity_distribution": {level: severity_counts.get(level, 0) for level in risk_engine.SEVERITY_ORDER},
                "category_distribution": dict(category_counts.most_common()),
                "scan_trend": [{"date": day, "count": count} for day, count in trend.items()],
                "risk_timeline": risk_timeline,
                "privacy_improvement": {
                    "percent": improvement,
                    "interpretation": "Positive means recent scans show lower risk than earlier scans.",
                },
                "recent_scans": ScanListSerializer(recent, many=True).data,
            }
        )


class RecommendationListView(APIView):
    def get(self, request):
        queryset = Recommendation.objects.filter(scan__user=request.user).select_related("scan").order_by("priority", "-id")[:80]
        return Response(RecommendationSerializer(queryset, many=True).data)


class FindingsView(APIView):
    def get(self, request):
        severity = request.query_params.get("severity")
        queryset = Finding.objects.filter(scan__user=request.user).select_related("scan")
        if severity in risk_engine.SEVERITY_ORDER:
            queryset = queryset.filter(severity=severity)
        return Response(FindingSerializer(queryset[:200], many=True).data)
