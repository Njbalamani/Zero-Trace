"""Unit tests for the privacy scanning engines."""

from __future__ import annotations

from io import BytesIO

from django.test import SimpleTestCase

from apps.engine import metadata_analyzer, redaction, risk_engine, text_detector
from apps.engine.document_scanner import scan_document
from apps.engine.sanitizer import sanitize_document


class RedactionTests(SimpleTestCase):
    def test_redaction_hides_raw_values(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        result = redaction.redact(secret, "api_key")
        self.assertNotIn(secret, result)
        self.assertIn("[REDACTED_API_KEY]", result)

    def test_label_redaction(self):
        label = "john.doe@example.com-report.pdf"
        self.assertNotIn("john.doe", redaction.redact_label(label))
        self.assertIn("[REDACTED_EMAIL]", redaction.redact_label(label))


class TextDetectorTests(SimpleTestCase):
    def test_detects_multiple_categories_and_redacts(self):
        content = (
            "Contact jane.doe@example.com or +1 (415) 555-0199.\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "db_password = 'SuperSecret123!'\n"
            "SSN: 123-45-6789\n"
            "Card: 4111 1111 1111 1111\n"
            "INTERNAL USE ONLY - project atlas\n"
        )
        findings = text_detector.detect_text(content)
        categories = {finding["category"] for finding in findings}
        self.assertTrue({"email", "phone", "api_key", "credential", "financial", "confidential"}.issubset(categories))
        for finding in findings:
            self.assertTrue(finding["redacted_evidence"].startswith("[REDACTED"))
            self.assertNotIn("SuperSecret123!", str(finding))

    def test_placeholder_values_are_not_reported_as_secrets(self):
        content = "api_key = '${API_KEY}'\npassword = 'changeme'\n"
        findings = text_detector.detect_text(content)
        self.assertFalse([item for item in findings if item["category"] in {"api_key", "credential"}])

    def test_luhn_validation(self):
        self.assertTrue(text_detector.patterns.is_likely_card("4111 1111 1111 1111"))
        self.assertFalse(text_detector.patterns.is_likely_card("4111 1111 1111 1112"))


class DocumentScannerTests(SimpleTestCase):
    def test_scan_pdf(self):
        import fitz

        document = fitz.open()
        page = document.new_page()
        page.insert_text((72, 72), "Owner: jane@example.com. AWS key: AKIAIOSFODNN7EXAMPLE")
        document.set_metadata({"author": "Jane Doe", "title": "Internal Report", "creator": "Internal Tool"})
        raw = document.tobytes()
        document.close()

        result = scan_document("quarterly.pdf", raw)
        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("email", categories)
        self.assertIn("api_key", categories)
        self.assertIn("metadata", categories)
        self.assertEqual(result["metadata"]["page_count"], 1)
        self.assertNotIn("Jane Doe", str(result["findings"]))

    def test_scan_docx(self):
        from docx import Document

        document = Document()
        document.add_paragraph("Reach me at jane@example.com. Phone: +1 415 555 0199")
        document.core_properties.author = "Jane Doe"
        document.core_properties.last_modified_by = "Internal User"
        buffer = BytesIO()
        document.save(buffer)

        result = scan_document("report.docx", buffer.getvalue())
        categories = {finding["category"] for finding in result["findings"]}
        self.assertIn("email", categories)
        self.assertIn("phone", categories)
        self.assertIn("metadata", categories)

    def test_unsupported_file_type(self):
        with self.assertRaises(ValueError):
            scan_document("malware.exe", b"data")

    def test_metadata_module_handles_empty_pdf(self):
        import fitz

        document = fitz.open()
        document.new_page()
        raw = document.tobytes()
        document.close()
        info, findings, _ = metadata_analyzer.analyze_pdf(raw)
        self.assertEqual(info["page_count"], 1)
        self.assertIsInstance(findings, list)


class SanitizerTests(SimpleTestCase):
    def test_docx_metadata_is_removed(self):
        from docx import Document

        document = Document()
        document.add_paragraph("Public content stays intact.")
        document.core_properties.author = "Jane Doe"
        document.core_properties.last_modified_by = "Internal User"
        buffer = BytesIO()
        document.save(buffer)

        cleaned, name, mime = sanitize_document("report.docx", buffer.getvalue())
        result = Document(BytesIO(cleaned))
        self.assertEqual(result.core_properties.author, "")
        self.assertEqual(result.core_properties.last_modified_by, "")
        self.assertEqual(result.paragraphs[0].text, "Public content stays intact.")
        self.assertTrue(name.endswith("-clean.docx"))
        self.assertIn("wordprocessingml", mime)

    def test_pdf_metadata_is_removed(self):
        import fitz

        document = fitz.open()
        document.new_page().insert_text((72, 72), "Public content")
        document.set_metadata({"author": "Jane Doe", "title": "Internal"})
        raw = document.tobytes()
        document.close()

        cleaned, name, mime = sanitize_document("report.pdf", raw)
        with fitz.open(stream=cleaned, filetype="pdf") as result:
            self.assertFalse(result.metadata.get("author"))
            self.assertFalse(result.metadata.get("title"))
            self.assertIn("Public content", result[0].get_text())
        self.assertTrue(name.endswith("-clean.pdf"))
        self.assertEqual(mime, "application/pdf")


class RiskEngineTests(SimpleTestCase):
    def test_score_and_recommendations(self):
        findings = [
            {"severity": "critical", "category": "api_key"},
            {"severity": "high", "category": "metadata"},
            {"severity": "medium", "category": "email"},
        ]
        summary = risk_engine.calculate_risk(findings)
        self.assertEqual(summary["score"], 25 + 15 + 7)
        self.assertEqual(summary["level"], "medium")
        self.assertEqual(summary["critical_count"], 1)
        recommendations = risk_engine.build_recommendations(findings)
        keys = {item["action_key"] for item in recommendations}
        self.assertIn("rotate_credentials", keys)
        self.assertIn("strip_metadata", keys)

    def test_ai_not_used_without_consent(self):
        summary = risk_engine.calculate_risk([{"severity": "low", "category": "email"}])
        narrative, used = risk_engine.ai_assessment(summary, [], consent=False)
        self.assertFalse(used)
        self.assertIn("Privacy scan identified", narrative)
