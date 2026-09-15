from django.contrib import admin

from .models import Share, ShareAccessLog


class ShareAccessLogInline(admin.TabularInline):
    model = ShareAccessLog
    extra = 0
    can_delete = False
    readonly_fields = ("accessed_at", "ip_address", "user_agent", "success", "reason")
    fields = readonly_fields
    ordering = ("-accessed_at",)

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Share)
class ShareAdmin(admin.ModelAdmin):
    # Deliberately excludes ciphertext/iv from list & only shows them
    # read-only (truncated) on the detail page -- admins can see that
    # a blob exists, never a usable secret without the browser-held key.
    list_display = (
        "id",
        "owner",
        "label",
        "created_at",
        "expires_at",
        "max_views",
        "view_count",
        "revoked",
        "status",
    )
    list_filter = ("revoked", "created_at")
    search_fields = ("id", "owner__username", "label", "token_hash")
    readonly_fields = (
        "id",
        "owner",
        "token_hash",
        "created_at",
        "view_count",
        "ciphertext_preview",
        "iv",
    )
    exclude = ("ciphertext",)
    inlines = [ShareAccessLogInline]

    def status(self, obj):
        return "active" if obj.is_active() else (obj.unavailable_reason() or "inactive")

    def ciphertext_preview(self, obj):
        blob = obj.ciphertext or ""
        return f"{blob[:24]}… ({len(blob)} base64 chars, opaque without client key)"

    ciphertext_preview.short_description = "Ciphertext (opaque)"

    def has_add_permission(self, request):
        # Shares must be created via the encrypted API flow, not the admin.
        return False


@admin.register(ShareAccessLog)
class ShareAccessLogAdmin(admin.ModelAdmin):
    list_display = ("id", "share", "accessed_at", "ip_address", "success", "reason")
    list_filter = ("success", "reason", "accessed_at")
    search_fields = ("share__id", "ip_address")
    readonly_fields = [f.name for f in ShareAccessLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
