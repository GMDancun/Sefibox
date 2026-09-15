from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.conf import settings
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.http import require_GET

from .forms import RegisterForm, ResendVerificationForm
from .tokens import email_verification_token


def _send_verification_email(request, user):
    """
    Build the emailed verification link and send it.

    The link encodes the user's primary key (base64) and a
    self-expiring, stateless token (see accounts/tokens.py) -- nothing
    sensitive is stored server-side to represent "a verification email
    was sent".

    IMPORTANT: the body is forced to plain 7-bit ASCII (encoding =
    "us-ascii" below). Without this, some SMTP/console pipelines
    (observed on Windows) choose quoted-printable transfer encoding,
    which inserts soft line-break characters ("=\\n") into long lines
    -- and those breaks can land in the middle of the verification
    token, corrupting the link when it's copied out of the terminal
    or a plain-text email client. Forcing us-ascii guarantees a single
    unbroken line for the URL and fails loudly (UnicodeEncodeError) if
    the template ever gains a non-ASCII character, instead of silently
    corrupting links.
    """
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    token = email_verification_token.make_token(user)
    verify_path = f"/accounts/verify/{uidb64}/{token}/"
    verify_url = request.build_absolute_uri(verify_path)

    subject = "Verify your SefiBox account"
    text_body = render_to_string(
        "accounts/email/verify_email.txt",
        {"user": user, "verify_url": verify_url},
    )

    email = EmailMessage(subject, text_body, settings.DEFAULT_FROM_EMAIL, [user.email])
    email.encoding = "us-ascii"  # forces Content-Transfer-Encoding: 7bit, no line-folding
    email.send(fail_silently=False)


def register(request):
    if request.user.is_authenticated:
        return redirect("shares:dashboard")

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()  # created with is_active=False
            _send_verification_email(request, user)
            return render(request, "accounts/verify_pending.html", {"email": user.email})
    else:
        form = RegisterForm()

    return render(request, "accounts/register.html", {"form": form})


@require_GET
def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and not user.is_active and email_verification_token.check_token(user, token):
        user.is_active = True
        user.save(update_fields=["is_active"])
        login(request, user)
        messages.success(request, "Email verified — welcome to SefiBox!")
        return redirect("shares:dashboard")

    if user is not None and user.is_active:
        # Already verified (e.g. link clicked twice, or reused stale tab).
        messages.info(request, "This account is already verified. Please log in.")
        return redirect("accounts:login")

    return render(request, "accounts/verify_invalid.html", status=400)


def resend_verification(request):
    if request.user.is_authenticated:
        return redirect("shares:dashboard")

    sent = False
    if request.method == "POST":
        form = ResendVerificationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            user = User.objects.filter(email__iexact=email, is_active=False).first()
            if user:
                _send_verification_email(request, user)
            # Always show the same message whether or not the account
            # exists / is already verified, to avoid leaking which
            # emails are registered.
            sent = True
    else:
        form = ResendVerificationForm()

    return render(request, "accounts/resend_verification.html", {"form": form, "sent": sent})
