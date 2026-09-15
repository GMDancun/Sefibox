import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class Share(models.Model):
    """
    An encrypted secret share.

    KrypBox never stores plaintext. `ciphertext` and `iv` are opaque
    base64 blobs produced by the browser's Web Crypto API; the
    AES-GCM key that would decrypt them is never sent to or stored by
    the server (it lives only in the recipient URL's fragment).

    `token_hash` stores SHA-256(raw_token) rather than the raw token
    itself, so that a database compromise does not directly hand out
    working share links.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="shares",
    )

    # Non-secret metadata, set by the owner, shown on their dashboard only.
    label = models.CharField(max_length=100, blank=True)

    # Opaque encrypted payload -- meaningless without the key in the URL
    # fragment. Sizes are bounded (validated in security.is_valid_base64).
    ciphertext = models.TextField()
    iv = models.CharField(max_length=64)  # base64-encoded AES-GCM nonce

    token_hash = models.CharField(max_length=64, unique=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    max_views = models.PositiveIntegerField(null=True, blank=True)
    view_count = models.PositiveIntegerField(default=0)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["owner", "-created_at"]),
        ]

    def __str__(self):
        return f"Share({self.id}) by {self.owner_id}"

    # -- status helpers -----------------------------------------------
    def is_expired(self) -> bool:
        return bool(self.expires_at and timezone.now() >= self.expires_at)

    def is_view_exhausted(self) -> bool:
        return bool(self.max_views and self.view_count >= self.max_views)

    def is_active(self) -> bool:
        return not (self.revoked or self.is_expired() or self.is_view_exhausted())

    def unavailable_reason(self) -> str:
        """Human-readable reason a share is not accessible, or '' if active."""
        if self.revoked:
            return "revoked"
        if self.is_expired():
            return "expired"
        if self.is_view_exhausted():
            return "max_views_exceeded"
        return ""

    def revoke(self):
        self.revoked = True
        self.revoked_at = timezone.now()
        self.save(update_fields=["revoked", "revoked_at"])


class ShareAccessLog(models.Model):
    """
    Audit trail of every access attempt against a share.

    Never contains plaintext or key material -- only metadata about
    the *attempt* (who/when/outcome). This lets an owner see who
    tried to view their secret and whether it succeeded, without the
    log itself becoming a sensitive artifact.
    """

    class Reason(models.TextChoices):
        VIEWED = "viewed", "Viewed"
        EXPIRED = "expired", "Expired"
        REVOKED = "revoked", "Revoked"
        MAX_VIEWS = "max_views_exceeded", "Max views exceeded"
        NOT_FOUND = "not_found", "Not found"

    share = models.ForeignKey(
        Share,
        on_delete=models.CASCADE,
        related_name="access_logs",
        null=True,
        blank=True,
    )
    accessed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    success = models.BooleanField(default=False)
    reason = models.CharField(max_length=32, choices=Reason.choices)

    class Meta:
        ordering = ["-accessed_at"]
        indexes = [
            models.Index(fields=["share", "-accessed_at"]),
        ]

    def __str__(self):
        return f"AccessLog(share={self.share_id}, {self.reason}, {self.accessed_at})"
