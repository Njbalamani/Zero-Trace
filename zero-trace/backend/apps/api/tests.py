"""Integration tests for authentication, scanning, redaction and reporting."""

from __future__ import annotations

import hashlib
from io import BytesIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from apps.scans.models import AuditEvent, Finding, RepositoryAuthorization, Scan

User = get_user_model()


def make_docx_with_secret() -> bytes:
    from docx import Document

    document = Document()
    document.add_paragraph("Contact jane@example.com. AWS key: AKIAIOSFODNN7EXAMPLE")
    document.core_properties.author = "Jane Doe"
    buffer = BytesIO()
    document.save(buffer)
    return buffer.getvalue()


class AuthFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_login_me_and_consent(self):
        response = self.client.post(
            "/api/auth/register/",
            {"username": "jane", "email": "jane@example.com", "password": "Str0ng!Passphrase42"},
            format="json",
        )
        self.assertEqual(response.status_code, 201)
        token = response.data["token"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        me = self.client.get("/api/auth/me/")
        self.assertEqual(me.status_code, 200)
        self.assertFalse(me.data["ai_consent"])

        consent = self.client.post("/api/auth/consent/", {"ai_consent": True}, format="json")
        self.assertEqual(consent.status_code, 200)
        self.assertTrue(consent.data["ai_consent"])

        self.client.credentials()
        login = self.client.post(
            "/api/auth/login/",
            {"email": "jane@example.com", "password": "Str0ng!Passphrase42"},
            format="json",
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.data["user"]["ai_consent"], True)

    def test_authentication_required(self):
        self.assertEqual(self.client.get("/api/scans/").status_code, 401)


class DocumentScanApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="jane", email="jane@example.com", password="Str0ng!Passphrase42")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.secret = "AKIAIOSFODNN7EXAMPLE"

    def test_document_scan_report_and_redaction(self):
        upload = SimpleUploadedFile("jane_doe_report.docx", make_docx_with_secret())
        response = self.client.post("/api/scans/documents/", {"file": upload}, format="multipart")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["status"], "completed")
        self.assertGreaterEqual(response.data["risk_score"], 25)

        serialized = str(response.data)
        self.assertNotIn(self.secret, serialized)
        self.assertNotIn("jane@example.com", serialized)
        self.assertIn("[REDACTED_EMAIL]", serialized)

        scan = Scan.objects.get(id=response.data["id"])
        self.assertEqual(scan.user, self.user)
        self.assertTrue(Finding.objects.filter(scan=scan).exists())
        self.assertNotIn(self.secret, scan.ai_summary)

        report = self.client.get(f"/api/scans/{scan.id}/report/")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report["Content-Type"], "application/pdf")
        pdf_bytes = b"".join(report.streaming_content)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertNotIn(self.secret.encode(), pdf_bytes)

    def test_invalid_file_type_rejected(self):
        upload = SimpleUploadedFile("bad.exe", b"MZ\x00\x01", content_type="application/octet-stream")
        response = self.client.post("/api/scans/documents/", {"file": upload}, format="multipart")
        self.assertEqual(response.status_code, 400)
        self.assertIn("PDF and DOCX", response.data["detail"])

    def test_other_users_scan_is_hidden(self):
        other = User.objects.create_user(username="other", email="other@example.com", password="Str0ng!Passphrase42")
        scan = Scan.objects.create(user=other, scan_type="document", source_name="other.pdf")
        self.assertEqual(self.client.get(f"/api/scans/{scan.id}/").status_code, 404)
        self.assertEqual(self.client.get(f"/api/scans/{scan.id}/report/").status_code, 404)

    def test_dashboard_aggregates(self):
        upload = SimpleUploadedFile("report.docx", make_docx_with_secret())
        self.client.post("/api/scans/documents/", {"file": upload}, format="multipart")
        dashboard = self.client.get("/api/dashboard/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.data["totals"]["documents"], 1)
        self.assertGreaterEqual(dashboard.data["totals"]["findings"], 3)
        self.assertIn("critical", dashboard.data["severity_distribution"])


    def test_batch_document_scan(self):
        uploads = [
            SimpleUploadedFile("alpha.docx", make_docx_with_secret()),
            SimpleUploadedFile("beta.docx", make_docx_with_secret()),
        ]
        response = self.client.post("/api/scans/documents/batch/", {"files": uploads}, format="multipart")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(len(response.data["completed"]), 2)
        self.assertEqual(response.data["failed"], [])
        self.assertEqual(Scan.objects.filter(user=self.user).count(), 2)

    def test_sanitize_endpoint_removes_metadata(self):
        from docx import Document

        upload = SimpleUploadedFile("private.docx", make_docx_with_secret())
        response = self.client.post("/api/tools/sanitize/", {"file": upload}, format="multipart")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Disposition"].endswith('private-clean.docx"'))
        cleaned = b"".join(response.streaming_content)
        document = Document(BytesIO(cleaned))
        self.assertEqual(document.core_properties.author, "")

    def test_false_positive_review_updates_risk_and_audit(self):
        upload = SimpleUploadedFile("report.docx", make_docx_with_secret())
        created = self.client.post("/api/scans/documents/", {"file": upload}, format="multipart")
        scan = Scan.objects.get(id=created.data["id"])
        original_score = scan.risk_score
        finding = scan.findings.first()

        response = self.client.post(f"/api/findings/{finding.id}/review/", {"false_positive": True}, format="json")
        self.assertEqual(response.status_code, 200)
        finding.refresh_from_db()
        scan.refresh_from_db()
        self.assertTrue(finding.false_positive)
        self.assertLessEqual(scan.risk_score, original_score)
        self.assertTrue(AuditEvent.objects.filter(user=self.user, action="finding_reviewed").exists())

    def test_audit_trail_and_risk_timeline(self):
        upload = SimpleUploadedFile("report.docx", make_docx_with_secret())
        self.client.post("/api/scans/documents/", {"file": upload}, format="multipart")
        audit = self.client.get("/api/audit/")
        self.assertEqual(audit.status_code, 200)
        self.assertTrue(any(event["action"] == "document_scan" for event in audit.data))

        dashboard = self.client.get("/api/dashboard/")
        self.assertEqual(len(dashboard.data["risk_timeline"]), 1)
        self.assertIn("score", dashboard.data["risk_timeline"][0])


class RepositoryScanApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="jane", email="jane@example.com", password="Str0ng!Passphrase42")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.token = "ghp_" + "a" * 36

    def test_authorization_is_required(self):
        response = self.client.post(
            "/api/scans/repositories/",
            {"repository": "acme/app", "token": self.token, "authorize": False},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Scan.objects.exists())

    @patch("apps.api.views.github_scanner.scan_repository")
    @patch("apps.api.views.github_scanner.validate_token")
    def test_authorized_scan_stores_only_token_fingerprint(self, mock_validate, mock_scan):
        mock_validate.return_value = hashlib.sha256(self.token.encode()).hexdigest()
        mock_scan.return_value = {
            "source_name": "acme/app",
            "source_hash": "abc123",
            "mime_type": "application/x-git-repository",
            "size_bytes": 42,
            "metadata": {"files_scanned": 1},
            "findings": [
                {
                    "category": "api_key",
                    "severity": "critical",
                    "title": "Possible github token",
                    "redacted_evidence": "[REDACTED_API_KEY] (fp:abcd, len:40)",
                    "redacted_context": "",
                    "fingerprint": "f" * 64,
                    "location": "config.py:L3",
                    "explanation": "Secret",
                    "remediation": "Rotate",
                    "source_tool": "regex",
                    "confidence": 0.99,
                }
            ],
        }
        response = self.client.post(
            "/api/scans/repositories/",
            {"repository": "acme/app", "token": self.token, "authorize": True},
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.data)
        authorization = RepositoryAuthorization.objects.get(user=self.user, repository="acme/app")
        self.assertEqual(authorization.token_fingerprint, hashlib.sha256(self.token.encode()).hexdigest())
        self.assertNotIn(self.token, str(authorization.token_fingerprint))
        self.assertEqual(Scan.objects.filter(scan_type="repository").count(), 1)
