# KrypBox

A secure secret-sharing platform. Secrets are encrypted **in the browser**
with the Web Crypto API (AES-GCM 256) before anything is sent to the
server. Django + PostgreSQL only ever store ciphertext, an IV, and a
*hash* of the share token — never plaintext, and never the decryption key.

Stack: Django 5.x, PostgreSQL, Django Templates + HTMX, vanilla JS
(Web Crypto API). No DRF, no React, no microservices.

## How the crypto works

1. **Create**: the owner types a secret. `static/js/crypto.js` generates
   a random AES-256 key in the browser, encrypts the plaintext, and
   POSTs only `{ciphertext, iv}` (both base64) to `/api/create/`.
   Django generates a random share token, stores `SHA-256(token)` (not
   the token itself) plus the ciphertext/IV, and returns a URL path.
   The browser appends `#<key>` to build the final link — the key
   lives only in the URL fragment, which browsers never send to any
   server.
2. **View**: a recipient opens `/s/<token>`. Django hashes the token,
   looks up the `Share`, checks revoked/expired/max-views, logs the
   attempt, and renders the ciphertext + IV into the page. Client-side
   JS reads the key from `window.location.hash` and decrypts with
   `crypto.subtle.decrypt`. The server process never has access to the
   key or the plaintext at any point.

## Project layout

```
config/            settings, root urls, wsgi/asgi
accounts/          registration + login/logout (Django's built-in User)
shares/
  models.py        Share, ShareAccessLog
  security.py      token generation/hashing, IP extraction, base64 validation
  views.py         dashboard, create (page + JSON API), revoke, public view
  admin.py         admin (ciphertext shown only as a redacted preview)
templates/         base + accounts + shares templates (HTMX for revoke)
static/js/crypto.js  Web Crypto API encrypt/decrypt + form wiring
static/css/style.css responsive dark UI
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # then edit values, especially DJANGO_SECRET_KEY and DB_*

# create the database (adjust to your local Postgres setup)
createdb krypbox

python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Visit `http://localhost:8000/accounts/register/` to create an account,
then `http://localhost:8000/create/` to create your first secret.

## Sending real emails (instead of console output)

By default (`DEBUG=True`), verification emails print to your terminal
instead of actually sending — that's `EMAIL_BACKEND=console` in `.env`.
To send real emails, switch to SMTP:

```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=youraddress@gmail.com
EMAIL_HOST_PASSWORD=your-16-char-app-password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=KrypBox <youraddress@gmail.com>
```

Then **restart `python manage.py runserver`** — Django only reads `.env`
at process start, so changes won't take effect on a running server.

**Gmail specifically** requires an "App Password", not your normal
account password:
1. Enable 2-Step Verification on your Google account.
2. Go to https://myaccount.google.com/apppasswords
3. Generate a password for "Mail" and use that 16-character value as
   `EMAIL_HOST_PASSWORD`.

**Other providers** (swap host/port accordingly):
| Provider | EMAIL_HOST | EMAIL_PORT | Notes |
|---|---|---|---|
| Gmail | smtp.gmail.com | 587 | Needs App Password |
| Outlook/Office365 | smtp.office365.com | 587 | Regular password often works |
| SendGrid | smtp.sendgrid.net | 587 | `EMAIL_HOST_USER=apikey`, password = your API key |
| Mailgun | smtp.mailgun.org | 587 | Use SMTP creds from Mailgun dashboard |
| Mailtrap (testing) | sandbox.smtp.mailtrap.io | 2525 | Safe inbox for dev — emails never leave Mailtrap |

If port 587 is blocked by your network/ISP, try port 465 with
`EMAIL_USE_SSL=True` instead of `EMAIL_USE_TLS=True` (only set one of
the two).

For production, a transactional email API (SendGrid, Mailgun, Postmark,
SES) via SMTP is more reliable than a personal Gmail account, which
Google may rate-limit or flag.

## Troubleshooting: "Link invalid or expired"

If a freshly generated verification link fails immediately, the most
common cause is the email body being encoded as quoted-printable
(which inserts `=\n` line-fold characters that can land inside the
long token when non-ASCII characters are present in the email
template). `templates/accounts/email/verify_email.txt` is kept
strictly ASCII for this reason — if you edit it, avoid smart quotes,
em dashes, or other non-ASCII characters, or the link may get
corrupted when copied out of a terminal.

Other things to check:
- Copy the *entire* URL, including everything after the last `/`.
- Don't let your terminal soft-wrap and accidentally include a
  trailing newline in the copied text.
- Links expire after `EMAIL_VERIFICATION_TIMEOUT_SECONDS` (default 3
  days) and are single-use — request a new one from
  `/accounts/verify/resend/` if needed.

## Security notes / production checklist

- Set `DJANGO_DEBUG=False`, a strong random `DJANGO_SECRET_KEY`, and a
  real `DJANGO_ALLOWED_HOSTS` in production.
- Serve over HTTPS and set `DJANGO_SECURE_SSL_REDIRECT`,
  `DJANGO_SESSION_COOKIE_SECURE`, `DJANGO_CSRF_COOKIE_SECURE` to `True`
  (these already default to `True` whenever `DEBUG=False`).
- Put KrypBox behind a reverse proxy that sets/strips
  `X-Forwarded-For` correctly — `shares/security.py:client_ip` trusts
  that header.
- Rotate `DJANGO_SECRET_KEY` and Postgres credentials via your secrets
  manager, not by committing `.env` (it's gitignored).
- The share link's fragment (`#key`) is sensitive — it's not sent to
  the server, but anyone with the *full* link (including the browser
  history of whoever it was sent through, e.g. an unencrypted chat
  tool) can decrypt it. Treat the link itself as the secret.
- `max_views` + `expires_at` + `revoke()` are the only access controls;
  there's no rate limiting on `/s/<token>/` in this MVP — consider
  adding one (e.g. django-ratelimit or a reverse-proxy rule) if you're
  worried about token brute-forcing (tokens are 256-bit random, so
  this is a defense-in-depth measure, not a critical gap).
