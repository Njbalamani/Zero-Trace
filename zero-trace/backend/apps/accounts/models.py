"""User model with explicit AI-processing consent."""

from __future__ import annotations

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    email = models.EmailField("email address", unique=True)
    ai_consent = models.BooleanField(
        default=False,
        help_text="Consent to send redacted finding metadata to an external AI provider.",
    )
    ai_consent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.email
