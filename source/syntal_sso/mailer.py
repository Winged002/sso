from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from flask import current_app, render_template


def _bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def smtp_status():
    cfg = current_app.config
    host = (cfg.get("SMTP_HOST") or "").strip()
    sender_raw = (cfg.get("SMTP_FROM_EMAIL") or cfg.get("SMTP_USERNAME") or "").strip()
    sender = parseaddr(sender_raw)[1] or sender_raw
    return {
        "configured": bool(host and sender),
        "host": host,
        "port": int(cfg.get("SMTP_PORT") or 587),
        "username_configured": bool(cfg.get("SMTP_USERNAME")),
        "sender_configured": bool(sender),
        "use_tls": _bool(cfg.get("SMTP_USE_TLS")),
        "use_ssl": _bool(cfg.get("SMTP_USE_SSL")),
    }


def probe_smtp():
    """Connect/authenticate without sending a message."""
    cfg = current_app.config
    status = smtp_status()
    if not status["configured"]:
        return False, "SMTP is not configured."
    try:
        with _connection() as server:
            server.noop()
        return True, "SMTP connection and authentication succeeded."
    except Exception as exc:
        current_app.logger.warning("SMTP readiness probe failed: %s", exc)
        return False, f"{type(exc).__name__}: {exc}"


def _connection():
    cfg = current_app.config
    host = (cfg.get("SMTP_HOST") or "").strip()
    port = int(cfg.get("SMTP_PORT") or 587)
    timeout = int(cfg.get("SMTP_TIMEOUT") or 12)
    if not host:
        raise RuntimeError("SMTP_HOST is not configured")
    context = ssl.create_default_context()
    if _bool(cfg.get("SMTP_USE_SSL")):
        server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
        server.ehlo()
        if _bool(cfg.get("SMTP_USE_TLS")):
            server.starttls(context=context)
            server.ehlo()
    username = (cfg.get("SMTP_USERNAME") or "").strip()
    password = cfg.get("SMTP_PASSWORD") or ""
    if username:
        server.login(username, password)
    return server


def send_transactional_email(*, to, subject, text_body, html_body, headers=None):
    cfg = current_app.config
    status = smtp_status()
    if not status["configured"]:
        return {"ok": False, "configured": False, "error": "SMTP is not configured."}
    sender_raw = (cfg.get("SMTP_FROM_EMAIL") or cfg.get("SMTP_USERNAME") or "").strip()
    parsed_name, parsed_email = parseaddr(sender_raw)
    sender_email = parsed_email or sender_raw
    sender_name = (cfg.get("SMTP_FROM_NAME") or parsed_name or "Syntal").strip()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, sender_email))
    msg["To"] = to
    reply_to = (cfg.get("SMTP_REPLY_TO") or "").strip()
    if reply_to:
        msg["Reply-To"] = reply_to
    for key, value in (headers or {}).items():
        if value:
            msg[key] = str(value)
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    try:
        with _connection() as server:
            refused = server.send_message(msg)
        if refused:
            return {"ok": False, "configured": True, "error": "SMTP server refused one or more recipients."}
        return {"ok": True, "configured": True, "error": None}
    except Exception as exc:
        current_app.logger.exception("Transactional email delivery failed")
        return {"ok": False, "configured": True, "error": f"{type(exc).__name__}: {exc}"}


def send_invitation_email(*, to, recipient_name=None, organization_name, role_name, inviter_name, accept_url):
    subject = f"You’re invited to {organization_name} on Syntal"
    html = render_template(
        "email/invitation.html",
        recipient_name=recipient_name,
        organization_name=organization_name,
        role_name=role_name,
        inviter_name=inviter_name,
        accept_url=accept_url,
        subject=subject,
    )
    text = f"""Syntal\n\nYou’ve been invited to {organization_name}.\n\nInvited by: {inviter_name}\nRole: {role_name}\n\nAccept invitation: {accept_url}\n\nIf you were not expecting this invitation, you can ignore this email.\n"""
    return send_transactional_email(
        to=to,
        subject=subject,
        text_body=text,
        html_body=html,
        headers={"X-Syntal-Message-Type": "organization-invitation"},
    )


def send_security_email(*, to, recipient_name=None, title, message, detail=None, action_url=None, action_label=None):
    subject = f"Syntal security · {title}"
    html = render_template(
        "email/security.html",
        recipient_name=recipient_name,
        title=title,
        message=message,
        detail=detail,
        action_url=action_url,
        action_label=action_label,
        subject=subject,
    )
    text = f"Syntal security\n\n{title}\n\n{message}\n"
    if detail:
        text += f"\n{detail}\n"
    if action_url:
        text += f"\n{action_label or 'Review account'}: {action_url}\n"
    return send_transactional_email(
        to=to,
        subject=subject,
        text_body=text,
        html_body=html,
        headers={"X-Syntal-Message-Type": "security-notification"},
    )
