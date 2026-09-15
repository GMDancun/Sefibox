import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from .forms import CreateShareForm
from .models import Share, ShareAccessLog
from .security import (
    client_ip,
    generate_share_token,
    hash_token,
    is_valid_base64,
)
from django.conf import settings


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@login_required
def dashboard(request):
    shares = request.user.shares.all().prefetch_related("access_logs")
    return render(request, "shares/dashboard.html", {"shares": shares})


# ---------------------------------------------------------------------------
# Create share (page + JSON API called by crypto.js after client-side encryption)
# ---------------------------------------------------------------------------
@login_required
def create_share(request):
    """Renders the create-share page. The actual secret is encrypted
    in the browser and submitted to `create_share_api`, never here."""
    form = CreateShareForm()
    return render(request, "shares/create.html", {"form": form})


@login_required
@require_POST
def create_share_api(request):
    """
    JSON endpoint: receives *already encrypted* data from the browser.

    Expected JSON body:
        {
            "ciphertext": "<base64>",
            "iv": "<base64>",
            "label": "optional string",
            "expires_hours": 24,
            "max_views": 1
        }

    The server never sees plaintext or the decryption key. It only
    generates the share token, hashes it for storage, and persists
    the opaque ciphertext blob.
    """
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON body."}, status=400)

    ciphertext = payload.get("ciphertext", "")
    iv = payload.get("iv", "")
    label = (payload.get("label") or "")[:100]

    if not is_valid_base64(ciphertext, settings.KRYPBOX_MAX_CIPHERTEXT_LENGTH):
        return JsonResponse({"error": "Invalid or oversized ciphertext."}, status=400)
    if not is_valid_base64(iv, 64):
        return JsonResponse({"error": "Invalid IV."}, status=400)

    try:
        expires_hours = int(payload.get("expires_hours", 0))
        max_views = int(payload.get("max_views", settings.KRYPBOX_DEFAULT_MAX_VIEWS))
    except (TypeError, ValueError):
        return JsonResponse({"error": "Invalid expiry/max_views."}, status=400)

    if expires_hours not in settings.KRYPBOX_EXPIRY_CHOICES_HOURS:
        return JsonResponse({"error": "Invalid expiry option."}, status=400)
    if not (1 <= max_views <= 100):
        return JsonResponse({"error": "max_views must be between 1 and 100."}, status=400)

    token = generate_share_token()
    share = Share.objects.create(
        owner=request.user,
        label=label,
        ciphertext=ciphertext,
        iv=iv,
        token_hash=hash_token(token),
        expires_at=timezone.now() + timezone.timedelta(hours=expires_hours),
        max_views=max_views,
    )

    share_path = reverse("shares:public_view", kwargs={"token": token})
    return JsonResponse(
        {
            "id": str(share.id),
            "share_path": share_path,  # key is appended client-side as #fragment
        },
        status=201,
    )


# ---------------------------------------------------------------------------
# Revoke (owner only, HTMX-friendly)
# ---------------------------------------------------------------------------
@login_required
@require_POST
def revoke_share(request, share_id):
    share = get_object_or_404(Share, id=share_id, owner=request.user)
    share.revoke()

    if request.headers.get("HX-Request"):
        return render(request, "shares/_share_row.html", {"share": share})
    return redirect("shares:dashboard")


# ---------------------------------------------------------------------------
# Public recipient view: /s/<token>
# ---------------------------------------------------------------------------
@require_GET
def public_share_view(request, token):
    """
    Recipient-facing page.

    Looks the share up by the *hash* of the provided token (the raw
    token is never stored). Logs the access attempt regardless of
    outcome. On success, renders the ciphertext + IV into the page as
    inert data attributes; static/js/crypto.js reads the decryption
    key from window.location.hash (never sent to the server) and
    decrypts entirely client-side.
    """
    token_hash = hash_token(token)
    share = Share.objects.filter(token_hash=token_hash).first()

    ip = client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:300]

    if share is None:
        ShareAccessLog.objects.create(
            share=None,
            ip_address=ip or None,
            user_agent=user_agent,
            success=False,
            reason=ShareAccessLog.Reason.NOT_FOUND,
        )
        return render(request, "shares/unavailable.html", {"reason": "not_found"}, status=404)

    reason = share.unavailable_reason()
    if reason:
        ShareAccessLog.objects.create(
            share=share,
            ip_address=ip or None,
            user_agent=user_agent,
            success=False,
            reason=reason,
        )
        return render(request, "shares/unavailable.html", {"reason": reason}, status=410)

    # Active: consume one view atomically-ish (accepted race window is fine
    # for an MVP; F() avoids lost updates under concurrent requests).
    from django.db.models import F

    Share.objects.filter(id=share.id).update(view_count=F("view_count") + 1)
    share.refresh_from_db(fields=["view_count"])

    ShareAccessLog.objects.create(
        share=share,
        ip_address=ip or None,
        user_agent=user_agent,
        success=True,
        reason=ShareAccessLog.Reason.VIEWED,
    )

    return render(
        request,
        "shares/public_view.html",
        {
            "ciphertext": share.ciphertext,
            "iv": share.iv,
            "label": share.label,
        },
    )
