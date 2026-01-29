import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from datetime import datetime
from typing import Optional


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _smtp_config():
    enabled = _env_bool("EMAIL_ENABLED", True)
    host = os.getenv("SMTP_HOST", "")
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    use_ssl = _env_bool("SMTP_USE_SSL", False)
    use_tls = _env_bool("SMTP_USE_TLS", True)

    port_env = os.getenv("SMTP_PORT", "")
    if port_env:
        try:
            port = int(port_env)
        except ValueError:
            port = 465 if use_ssl else 587
    else:
        port = 465 if use_ssl else 587

    from_email = os.getenv("EMAIL_FROM", "") or username
    from_name = os.getenv("EMAIL_FROM_NAME", "Bigoh")

    return {
        "enabled": enabled,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "use_ssl": use_ssl,
        "use_tls": use_tls,
        "from_email": from_email,
        "from_name": from_name,
    }


def _app_base_url() -> str:
    return os.getenv("APP_BASE_URL", "").rstrip("/")


def _cta_url(path: str) -> str:
    base = _app_base_url()
    if not base:
        return "#"
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _build_email_html(title_line: str, body_lines: list, cta_text: str, cta_url: str) -> str:
    safe_lines = "".join(f"<p style=\"margin:0 0 10px;\">{line}</p>" for line in body_lines)
    return f"""\
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#ffffff;font-family:Arial,sans-serif;color:#111111;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#ffffff;">
      <tr>
        <td align="center" style="padding:32px 16px;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:460px;">
            <tr>
              <td align="center" style="padding-bottom:16px;">
                <a href="{cta_url}" style="color:#e11d48;text-decoration:underline;font-size:16px;">{title_line}</a>
              </td>
            </tr>
            <tr>
              <td align="center" style="padding-bottom:18px;">
                <a href="{cta_url}" style="display:inline-block;border:1px solid #d1d5db;border-radius:999px;padding:14px 30px;font-weight:600;color:#111111;text-decoration:none;">{cta_text}</a>
              </td>
            </tr>
            <tr>
              <td style="font-size:14px;line-height:1.6;color:#111111;">
                {safe_lines}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


def send_email(to_email: str, subject: str, text_body: str, html_body: Optional[str] = None):
    cfg = _smtp_config()
    if not cfg["enabled"]:
        print("Email disabled by EMAIL_ENABLED=0.")
        return None
    if not to_email or "@" not in to_email:
        print("Email not sent: invalid recipient.")
        return None
    if not cfg["host"] or not cfg["from_email"]:
        print("Email not configured: missing SMTP_HOST or EMAIL_FROM/SMTP_USERNAME.")
        return None

    msg = EmailMessage()
    msg["From"] = formataddr((cfg["from_name"], cfg["from_email"]))
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body or "")
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if cfg["use_ssl"]:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context) as server:
                if cfg["username"] and cfg["password"]:
                    server.login(cfg["username"], cfg["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
                server.ehlo()
                if cfg["use_tls"]:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if cfg["username"] and cfg["password"]:
                    server.login(cfg["username"], cfg["password"])
                server.send_message(msg)
        return True
    except Exception as error:
        print("Error sending email:", error)
        return None


def build_signup_email(name: str, store_name: str = "Bigoh"):
    now = datetime.now().strftime("%b %d, %Y %I:%M %p")
    subject = f"Welcome to {store_name}!"
    cta_url = _cta_url("signin")
    text = (
        f"Hi {name},\n\n"
        f"Thanks for creating your {store_name} account. Your registration was successful on {now}.\n"
        "If this wasn't you, please contact support immediately.\n\n"
        f"- {store_name} Team\n"
    )
    html = _build_email_html(
        "login in with SMS",
        [
            f"Hi {name},",
            f"Thanks for creating your {store_name} account. Your registration was successful on <strong>{now}</strong>.",
            "If this wasn't you, please contact support immediately.",
            f"- {store_name} Team",
        ],
        "Login Via Bigoh",
        cta_url,
    )
    return subject, text, html


def build_signin_email(name: str, store_name: str = "Bigoh", ip: Optional[str] = None):
    now = datetime.now().strftime("%b %d, %Y %I:%M %p")
    subject = f"New sign-in to your {store_name} account"
    cta_url = _cta_url("signin")
    ip_line = f"IP address: {ip}\n" if ip else ""
    text = (
        f"Hi {name},\n\n"
        f"We noticed a sign-in to your {store_name} account on {now}.\n"
        f"{ip_line}"
        "If this wasn't you, please reset your password and contact support.\n\n"
        f"- {store_name} Team\n"
    )
    body_lines = [
        f"Hi {name},",
        f"We noticed a sign-in to your {store_name} account on <strong>{now}</strong>.",
    ]
    if ip:
        body_lines.append(f"IP address: <strong>{ip}</strong>")
    body_lines.extend(
        [
            "If this wasn't you, please reset your password and contact support.",
            f"- {store_name} Team",
        ]
    )
    html = _build_email_html(
        "login in with SMS",
        body_lines,
        "Login Via Bigoh",
        cta_url,
    )
    return subject, text, html

