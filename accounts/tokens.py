from django.contrib.auth.tokens import PasswordResetTokenGenerator


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    """
    Generates the token embedded in the "verify your email" link.

    Reuses Django's battle-tested PasswordResetTokenGenerator machinery
    (HMAC over a timestamp + a hash derived from mutable user state) but
    mixes in `is_active` and `email` instead of `last_login`/password
    hash. That means:

      * the token automatically expires once the account is verified
        (is_active flips True -> hash changes -> old links stop working),
      * a token minted for one email address is invalidated if the user
        changes their email before clicking it,
      * no extra database table or stored token is required -- the
        token is self-verifying and expires via
        PASSWORD_RESET_TIMEOUT (settings), reused here for simplicity.
    """

    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{user.is_active}{user.email}{timestamp}"


email_verification_token = EmailVerificationTokenGenerator()
