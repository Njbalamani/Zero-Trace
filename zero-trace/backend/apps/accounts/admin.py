"""Admin registration for user accounts."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class ZeroTraceUserAdmin(UserAdmin):
    list_display = ("email", "username", "is_staff", "ai_consent", "created_at")
    search_fields = ("email", "username")
    ordering = ("email",)
    fieldsets = UserAdmin.fieldsets + (
        ("Privacy preferences", {"fields": ("ai_consent", "ai_consent_at", "created_at")}),
    )
    readonly_fields = ("created_at", "ai_consent_at")
