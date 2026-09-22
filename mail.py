import os
import smtplib
from email.message import EmailMessage

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "noreply@example.com")


def send_invite_email(to_email: str, link: str) -> bool:
    """Returns False (no-op) if SMTP isn't configured, so callers fall back to showing the link."""
    if not SMTP_HOST:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Loi moi tao tai khoan - KFM DHCP Tool"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(
        f"Ban duoc moi tao tai khoan operator cho KFM DHCP Tool.\n\n"
        f"Nhan vao link sau de tao mat khau: {link}\n\n"
        f"Link het han sau 24 gio."
    )
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
    return True
