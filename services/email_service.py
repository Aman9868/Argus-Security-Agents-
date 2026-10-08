"""Automated Email Alert & Human-in-the-Loop (HITL) Dispatcher for Cyber Sentinel.

Generates responsive security incident alert emails with sanitized secret previews
and cryptographic Human-in-the-Loop action triggers.
Supports standard SMTP with an automatic Local Outbox Fallback for development.
"""

import os
import smtplib
import asyncio
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List, Optional
import structlog
from apps.api.config import settings

logger = structlog.get_logger(__name__)

# In-memory Outbox store for local development and UI inspection
LOCAL_OUTBOX: List[Dict[str, Any]] = []


class EmailService:
    """Manages email templating, SMTP transmission, and HITL interactive dispatch."""

    @classmethod
    def generate_html_alert(
        cls,
        recipient_email: str,
        scan_id: str,
        target_path: str,
        target_type: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        findings: List[Dict[str, Any]],
        git_branch: Optional[str] = None,
        git_commit: Optional[str] = None
    ) -> str:
        """Constructs an enterprise dark-mode HTML security incident alert."""
        base_url = settings.HITL_BASE_URL.rstrip("/")
        project_name = os.path.basename(target_path.rstrip("/")) or target_path

        findings_rows = ""
        for f in findings[:15]:
            sev = f.get("severity", "HIGH")
            sev_color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else "#eab308")
            token = f.get("hitl_token", "")
            finding_id = f.get("finding_id", "")
            rule_name = f.get("rule_name", "Unknown Secret")
            file_loc = f.get("file_path", "unknown")
            line_no = f.get("line_number")
            loc_str = f"{file_loc}:{line_no}" if line_no else file_loc
            masked = f.get("masked_value", "****")
            verdict = f.get("ai_verdict", "UNASSESSED")

            remediate_link = f"{base_url}/api/credentials/hitl-action/{token}?action=REMEDIATED"
            suppress_link = f"{base_url}/api/credentials/hitl-action/{token}?action=ACCEPTED_RISK"
            fp_link = f"{base_url}/api/credentials/hitl-action/{token}?action=FALSE_POSITIVE"

            findings_rows += f"""
            <tr style="border-bottom: 1px solid #2d3748;">
              <td style="padding: 12px 10px; font-weight: bold; color: {sev_color};">
                <span style="background: {sev_color}22; border: 1px solid {sev_color}; padding: 3px 8px; border-radius: 4px; font-size: 11px;">{sev}</span>
              </td>
              <td style="padding: 12px 10px; color: #f7fafc; font-size: 13px;">
                <div style="font-weight: 600;">{rule_name}</div>
                <div style="color: #a0aec0; font-family: monospace; font-size: 11px; margin-top: 3px;">{loc_str}</div>
              </td>
              <td style="padding: 12px 10px; font-family: monospace; color: #cbd5e0; font-size: 12px;">
                <code style="background: #1a202c; padding: 2px 6px; border-radius: 4px; border: 1px solid #4a5568;">{masked}</code>
                <div style="color: #718096; font-size: 10px; margin-top: 2px;">AI: {verdict}</div>
              </td>
              <td style="padding: 12px 10px; text-align: right; white-space: nowrap;">
                <a href="{remediate_link}" style="background: #dc2626; color: #ffffff; padding: 5px 9px; text-decoration: none; border-radius: 4px; font-size: 11px; font-weight: bold; margin-right: 4px; display: inline-block;">Remediate</a>
                <a href="{suppress_link}" style="background: #4b5563; color: #e5e7eb; padding: 5px 9px; text-decoration: none; border-radius: 4px; font-size: 11px; margin-right: 4px; display: inline-block;">Accept</a>
                <a href="{fp_link}" style="background: #374151; color: #9ca3af; padding: 5px 9px; text-decoration: none; border-radius: 4px; font-size: 11px; display: inline-block;">False +</a>
              </td>
            </tr>
            """

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Cyber Sentinel — Credential Leaks Incident</title>
        </head>
        <body style="background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 24px;">
          <div style="max-width: 780px; margin: 0 auto; background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #1f2937 0%, #111827 100%); padding: 24px; border-bottom: 2px solid #ef4444;">
              <table style="width: 100%;">
                <tr>
                  <td>
                    <div style="display: inline-block; font-size: 20px; font-weight: 800; color: #f87171; letter-spacing: 0.5px;">
                      🛡️ CYBER SENTINEL XDR
                    </div>
                    <div style="color: #9ca3af; font-size: 12px; margin-top: 4px;">AUTOMATED CREDENTIAL & SECRET LEAK INCIDENT REPORT</div>
                  </td>
                  <td style="text-align: right;">
                    <span style="background-color: #dc2626; color: white; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase;">
                      ACTION REQUIRED (HITL)
                    </span>
                  </td>
                </tr>
              </table>
            </div>

            <!-- Content Area -->
            <div style="padding: 24px;">
              <h2 style="color: #ffffff; font-size: 18px; margin-top: 0; margin-bottom: 8px;">
                🚨 Potential Credential Exposure Detected: <span style="color: #38bdf8;">{project_name}</span>
              </h2>
              <p style="color: #9ca3af; font-size: 14px; line-height: 1.5; margin-top: 0;">
                The Cyber Sentinel automated secret scanner identified <strong>{total_findings}</strong> hardcoded credentials or sensitive files in the scanned codebase. Review and authorization are requested under the Human-in-the-Loop security policy.
              </p>

              <!-- Metrics Grid -->
              <table style="width: 100%; border-collapse: separate; border-spacing: 8px; margin: 20px 0;">
                <tr>
                  <td style="background: #1c2333; padding: 12px; border-radius: 6px; text-align: center; border: 1px solid #30363d;">
                    <div style="font-size: 11px; color: #9ca3af;">TOTAL LEAKS</div>
                    <div style="font-size: 22px; font-weight: bold; color: #ffffff; margin-top: 4px;">{total_findings}</div>
                  </td>
                  <td style="background: #450a0a; padding: 12px; border-radius: 6px; text-align: center; border: 1px solid #7f1d1d;">
                    <div style="font-size: 11px; color: #fca5a5;">CRITICAL</div>
                    <div style="font-size: 22px; font-weight: bold; color: #ef4444; margin-top: 4px;">{critical_count}</div>
                  </td>
                  <td style="background: #431407; padding: 12px; border-radius: 6px; text-align: center; border: 1px solid #9a3412;">
                    <div style="font-size: 11px; color: #fdba74;">HIGH</div>
                    <div style="font-size: 22px; font-weight: bold; color: #f97316; margin-top: 4px;">{high_count}</div>
                  </td>
                  <td style="background: #3b2a05; padding: 12px; border-radius: 6px; text-align: center; border: 1px solid #854d0e;">
                    <div style="font-size: 11px; color: #fde047;">MEDIUM / LOW</div>
                    <div style="font-size: 22px; font-weight: bold; color: #eab308; margin-top: 4px;">{medium_count + low_count}</div>
                  </td>
                </tr>
              </table>

              <!-- Target Telemetry -->
              <div style="background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px 16px; font-size: 12px; color: #8b949e; margin-bottom: 20px;">
                <div><strong>Target Path:</strong> <span style="font-family: monospace; color: #c9d1d9;">{target_path}</span></div>
                <div><strong>Source Type:</strong> {target_type} | <strong>Branch:</strong> {git_branch or 'N/A'} | <strong>Commit:</strong> {git_commit or 'N/A'}</div>
                <div><strong>Scan ID:</strong> {scan_id}</div>
              </div>

              <!-- Findings Table -->
              <h3 style="color: #ffffff; font-size: 14px; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px;">
                Detected Leaks &amp; Immediate HITL Actions
              </h3>
              <table style="width: 100%; border-collapse: collapse; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; overflow: hidden;">
                <thead>
                  <tr style="background: #161b22; text-align: left; font-size: 11px; color: #8b949e; text-transform: uppercase; border-bottom: 1px solid #30363d;">
                    <th style="padding: 10px;">Severity</th>
                    <th style="padding: 10px;">Detector / Location</th>
                    <th style="padding: 10px;">Masked Preview</th>
                    <th style="padding: 10px; text-align: right;">HITL Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {findings_rows}
                </tbody>
              </table>

              <!-- Main Console CTA -->
              <div style="text-align: center; margin-top: 24px; padding-top: 20px; border-top: 1px solid #30363d;">
                <a href="{base_url}/" style="background: #2563eb; color: #ffffff; text-decoration: none; padding: 10px 24px; border-radius: 6px; font-size: 13px; font-weight: bold; display: inline-block;">
                  Open Cyber Sentinel XDR Security Console
                </a>
              </div>
            </div>

            <!-- Footer -->
            <div style="background: #0d1117; padding: 16px 24px; border-top: 1px solid #30363d; font-size: 11px; color: #6e7681; text-align: center;">
              This notification was generated automatically by the Cyber Sentinel Credential Leaks Sentinel.<br/>
              Raw credential values have been cryptographically masked to prevent secondary exposure.
            </div>
          </div>
        </body>
        </html>
        """
        return html_body

    @classmethod
    async def send_alert_email(
        cls,
        recipient_email: str,
        scan_id: str,
        target_path: str,
        target_type: str,
        total_findings: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        findings: List[Dict[str, Any]],
        git_branch: Optional[str] = None,
        git_commit: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sends the HTML alert via SMTP or falls back gracefully to the Local Outbox."""
        project_name = os.path.basename(target_path.rstrip("/")) or target_path
        subject = f"🚨 [Cyber Sentinel] CRITICAL: Credential Leaks Detected in {project_name}"
        html_content = cls.generate_html_alert(
            recipient_email=recipient_email,
            scan_id=scan_id,
            target_path=target_path,
            target_type=target_type,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            findings=findings,
            git_branch=git_branch,
            git_commit=git_commit
        )

        outbox_entry = {
            "email_id": f"mail_{int(time.time())}_{scan_id[:8]}",
            "scan_id": scan_id,
            "recipient": recipient_email,
            "from_email": settings.SMTP_FROM_EMAIL,
            "subject": subject,
            "html_content": html_content,
            "findings_count": total_findings,
            "sent_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "status": "QUEUED"
        }

        # Attempt SMTP delivery if configured
        smtp_success = False
        smtp_error = None

        if settings.SMTP_HOST and settings.SMTP_HOST != "localhost":
            def _send_sync():
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = settings.SMTP_FROM_EMAIL
                msg["To"] = recipient_email

                part = MIMEText(html_content, "html")
                msg.attach(part)

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10.0) as server:
                    if settings.SMTP_TLS:
                        server.starttls()
                    if settings.SMTP_USER and settings.SMTP_PASSWORD:
                        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.send_message(msg)

            try:
                await asyncio.to_thread(_send_sync)
                smtp_success = True
                outbox_entry["status"] = "SENT_VIA_SMTP"
                logger.info("Credential leak alert sent via SMTP", recipient=recipient_email, scan_id=scan_id)
            except Exception as e:
                smtp_error = str(e)
                outbox_entry["status"] = "SAVED_TO_LOCAL_OUTBOX"
                outbox_entry["error"] = smtp_error
                logger.warning("SMTP delivery failed, falling back to Local Outbox", error=smtp_error)
        else:
            outbox_entry["status"] = "SAVED_TO_LOCAL_OUTBOX"
            logger.info("Local environment: Alert saved to Cyber Sentinel Outbox", recipient=recipient_email)

        # Store in Outbox
        LOCAL_OUTBOX.insert(0, outbox_entry)
        if len(LOCAL_OUTBOX) > 50:
            LOCAL_OUTBOX.pop()

        return {
            "delivered": smtp_success,
            "outbox_status": outbox_entry["status"],
            "recipient": recipient_email,
            "subject": subject,
            "email_id": outbox_entry["email_id"],
            "smtp_error": smtp_error
        }

    @classmethod
    def get_outbox_messages(cls, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns recent outbox messages for UI inspection."""
        return LOCAL_OUTBOX[:limit]

