from email.message import EmailMessage
import smtplib

from app.core.config import settings


def send_password_reset_email(recipient_email: str, reset_url: str) -> None:
    if not settings.SMTP_USERNAME:
        raise RuntimeError("SMTP_USERNAME is not configured.")

    if not settings.SMTP_PASSWORD:
        raise RuntimeError("SMTP_PASSWORD is not configured.")

    # Keep the requested NetSecure sender identity for now.
    sender_email = settings.SMTP_FROM_EMAIL or "noreply@netsecureanalyzer.com"

    message = EmailMessage()
    message["Subject"] = "Reset your NetSecure Analyzer password"
    message["From"] = f"NetSecure Analyzer <{sender_email}>"
    message["To"] = recipient_email

    # Plain-text fallback for email clients that do not render HTML.
    message.set_content(
        f"""NETSECURE ANALYZER

Reset your password

We received a request to reset your NetSecure Analyzer password.

Reset Password:
{reset_url}

This link expires in {settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes
and can only be used once.

If you didn't request this password reset, you can safely ignore this email.

NetSecure Analyzer
AI-Driven Network Security Compliance Platform

This is an automated security email. Please do not reply.
"""
    )

    # HTML version.
    message.add_alternative(
        f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset your NetSecure Analyzer password</title>
</head>

<body style="
    margin:0;
    padding:0;
    background:#f4f7fb;
    font-family:Arial,Helvetica,sans-serif;
    color:#17233a;
">

<table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    border="0"
    style="background:#f4f7fb;"
>
    <tr>
        <td align="center" style="padding:48px 16px;">

            <!-- Main card -->
            <table
                role="presentation"
                width="100%"
                cellspacing="0"
                cellpadding="0"
                border="0"
                style="
                    max-width:560px;
                    background:#ffffff;
                    border:1px solid #e2e8f0;
                    border-radius:12px;
                    overflow:hidden;
                "
            >

                <!-- Brand -->
                <tr>
                    <td style="
                        padding:30px 40px 26px;
                        border-bottom:1px solid #edf1f5;
                    ">

                        <div style="
                            font-size:17px;
                            line-height:1.3;
                            font-weight:700;
                            letter-spacing:1.1px;
                            color:#17233a;
                        ">
                            NETSECURE ANALYZER
                        </div>

                        <div style="
                            margin-top:6px;
                            font-size:12px;
                            line-height:1.5;
                            color:#64748b;
                        ">
                            AI-Driven Network Security Compliance Platform
                        </div>

                    </td>
                </tr>

                <!-- Content -->
                <tr>
                    <td style="padding:42px 40px 40px;">

                        <h1 style="
                            margin:0 0 18px;
                            font-size:29px;
                            line-height:1.25;
                            font-weight:700;
                            color:#17233a;
                        ">
                            Reset your password
                        </h1>

                        <p style="
                            margin:0 0 25px;
                            font-size:15px;
                            line-height:1.7;
                            color:#475569;
                        ">
                            We received a request to reset your
                            NetSecure Analyzer password.
                        </p>

                        <p style="
                            margin:0 0 28px;
                            font-size:15px;
                            line-height:1.7;
                            color:#475569;
                        ">
                            Click the button below to choose a new password.
                        </p>

                        <!-- CTA -->
                        <table
                            role="presentation"
                            cellspacing="0"
                            cellpadding="0"
                            border="0"
                            style="margin:0 0 30px;"
                        >
                            <tr>
                                <td
                                    align="center"
                                    style="
                                        border-radius:8px;
                                        background:#17233a;
                                    "
                                >
                                    <a
                                        href="{reset_url}"
                                        style="
                                            display:inline-block;
                                            padding:14px 25px;
                                            border-radius:8px;
                                            font-size:15px;
                                            line-height:1;
                                            font-weight:700;
                                            color:#ffffff;
                                            text-decoration:none;
                                        "
                                    >
                                        Reset Password
                                    </a>
                                </td>
                            </tr>
                        </table>

                        <!-- Expiration notice -->
                        <table
                            role="presentation"
                            width="100%"
                            cellspacing="0"
                            cellpadding="0"
                            border="0"
                            style="
                                margin:0 0 26px;
                                background:#f8fafc;
                                border:1px solid #e2e8f0;
                                border-radius:8px;
                            "
                        >
                            <tr>
                                <td style="padding:16px 18px;">

                                    <p style="
                                        margin:0;
                                        font-size:13px;
                                        line-height:1.6;
                                        color:#475569;
                                    ">
                                        This link expires in
                                        <strong>
                                            {settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes
                                        </strong>
                                        and can only be used once.
                                    </p>

                                </td>
                            </tr>
                        </table>

                        <!-- Security note -->
                        <p style="
                            margin:0;
                            font-size:13px;
                            line-height:1.7;
                            color:#64748b;
                        ">
                            If you didn't request this password reset,
                            you can safely ignore this email.
                        </p>

                    </td>
                </tr>

                <!-- Footer -->
                <tr>
                    <td style="
                        padding:24px 40px;
                        background:#f8fafc;
                        border-top:1px solid #edf1f5;
                    ">

                        <p style="
                            margin:0;
                            font-size:13px;
                            line-height:1.5;
                            font-weight:600;
                            color:#475569;
                        ">
                            NetSecure Analyzer
                        </p>

                        <p style="
                            margin:4px 0 0;
                            font-size:12px;
                            line-height:1.5;
                            color:#94a3b8;
                        ">
                            AI-Driven Network Security Compliance Platform
                        </p>

                    </td>
                </tr>

            </table>

            <!-- Automated email notice -->
            <p style="
                margin:18px 0 0;
                font-size:11px;
                line-height:1.5;
                color:#94a3b8;
                text-align:center;
            ">
                This is an automated security email. Please do not reply.
            </p>

        </td>
    </tr>
</table>

</body>
</html>
""",
        subtype="html",
    )

    # Gmail SMTP with STARTTLS.
    with smtplib.SMTP(
        settings.SMTP_HOST,
        settings.SMTP_PORT,
        timeout=20,
    ) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(
            settings.SMTP_USERNAME,
            settings.SMTP_PASSWORD,
        )
        server.send_message(message)