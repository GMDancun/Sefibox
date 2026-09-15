from django import forms
from django.conf import settings


def _label_for_hours(hours: int) -> str:
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''}"
    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''}"


class CreateShareForm(forms.Form):
    """
    Metadata-only form rendered on the create-share page.

    The actual secret is never submitted through this form as
    plaintext. static/js/crypto.js intercepts the submit event,
    encrypts the plaintext client-side in the browser, and POSTs JSON
    (ciphertext + iv + this metadata) to shares:create_api.
    """

    label = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(
            attrs={"class": "input", "placeholder": "e.g. Prod DB password (optional)"}
        ),
    )
    expires_hours = forms.ChoiceField(
        choices=[(h, _label_for_hours(h)) for h in settings.KRYPBOX_EXPIRY_CHOICES_HOURS],
        required=True,
        widget=forms.Select(attrs={"class": "input"}),
    )
    max_views = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=settings.KRYPBOX_DEFAULT_MAX_VIEWS,
        widget=forms.NumberInput(attrs={"class": "input"}),
    )
