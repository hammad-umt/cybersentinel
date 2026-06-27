"""Transactional email delivery for password reset (Resend API or SMTP)."""

from __future__ import annotations

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import httpx
from loguru import logger

from core.config import settings


def build_password_reset_link(token: str) -> str:
    base = settings.FRONTEND_RESET_PASSWORD_URL.rstrip("/")
    return f"{base}?token={token}"


def _password_reset_content(reset_link: str) -> tuple[str, str, str]:
    subject = f"{settings.APP_NAME} — Reset your password"
    plain = (
        f"You requested a password reset for your {settings.APP_NAME} account.\n\n"
        f"Open this link to choose a new password (expires in "
        f"{settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes):\n\n"
        f"{reset_link}\n\n"
        "If you did not request this, you can ignore this email."
    )
    html = f"""\
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.5; color: #1a1a1a;">
  <h2>{settings.APP_NAME}</h2>
  <p>You requested a password reset for your account.</p>
  <p>
    <a href="{reset_link}" style="display:inline-block;padding:10px 18px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px;">
      Reset password
    </a>
  </p>
  <p>Or copy this link into your browser:</p>
  <p><a href="{reset_link}">{reset_link}</a></p>
  <p style="color:#666;font-size:13px;">
    This link expires in {settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} minutes.
    If you did not request a reset, you can ignore this email.
  </p>
</body>
</html>
"""
    return subject, plain, html


def _from_address() -> str:
    return f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"


async def _send_via_resend(*, to_email: str, reset_link: str) -> None:
    subject, plain, html = _password_reset_content(reset_link)
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": _from_address(),
                "to": [to_email],
                "subject": subject,
                "html": html,
                "text": plain,
            },
        )
        response.raise_for_status()


def _send_via_smtp_sync(*, to_email: str, reset_link: str) -> None:
    subject, plain, html = _password_reset_content(reset_link)

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = _from_address()
    message["To"] = to_email
    message.attach(MIMEText(plain, "plain", "utf-8"))
    message.attach(MIMEText(html, "html", "utf-8"))

    if settings.SMTP_USE_TLS:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM_EMAIL, [to_email], message.as_string())
    else:
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
            if settings.SMTP_USER:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM_EMAIL, [to_email], message.as_string())


async def send_password_reset_email(*, to_email: str, reset_link: str) -> bool:
    """Send password reset email via Resend (preferred) or SMTP."""
    if not settings.email_configured:
        logger.error("Email service is not configured — set RESEND_API_KEY or SMTP_* in .env")
        return False

    try:
        if settings.resend_configured:
            await _send_via_resend(to_email=to_email, reset_link=reset_link)
        else:
            await asyncio.to_thread(
                _send_via_smtp_sync,
                to_email=to_email,
                reset_link=reset_link,
            )
        logger.info("Password reset email sent to {email}", email=to_email)
        return True
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Resend rejected password reset email to {email}: {status} {body}",
            email=to_email,
            status=exc.response.status_code,
            body=exc.response.text,
        )
        return False
    except Exception as exc:
        logger.error("Failed to send password reset email to {email}: {err}", email=to_email, err=exc)
        return False
