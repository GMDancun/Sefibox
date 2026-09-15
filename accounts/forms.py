from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


class RegisterForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={"class": "input", "autocomplete": "email"}),
    )

    class Meta:
        model = User
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.widget.attrs.setdefault("class", "input")
            if name != "email":
                field.widget.attrs.setdefault("autocomplete", "off")

    def clean_email(self):
        email = self.cleaned_data["email"].lower().strip()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        # Account stays inactive until the emailed verification link is
        # clicked -- see accounts/views.py:register / verify_email.
        user.is_active = False
        if commit:
            user.save()
        return user


class ResendVerificationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "input", "autocomplete": "email", "placeholder": "you@example.com"})
    )


class EmailVerificationAuthenticationForm(AuthenticationForm):
    """
    Standard Django login form, but with a tailored error message (and
    a resend link, rendered by the template) when the account exists
    but hasn't clicked its verification email yet.
    """

    def confirm_login_allowed(self, user):
        if not user.is_active:
            raise ValidationError(
                "Please verify your email address before logging in. "
                "Check your inbox, or request a new verification link below.",
                code="inactive",
            )
