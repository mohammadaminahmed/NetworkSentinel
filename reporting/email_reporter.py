import smtplib
import os
from email.message import EmailMessage
from core.logger import log

def send_daily_report(config, report_path="reports/report.html"):
    notifications = config.settings.get("notifications", {})
    if not notifications.get("email_enabled", False):
        log.info("Email reporting is disabled in configuration.")
        return

    sender = notifications.get("email_sender", "")
    password = notifications.get("email_password", "")
    receiver = notifications.get("email_receiver", "")
    smtp_server = notifications.get("smtp_server", "smtp.gmail.com")
    smtp_port = notifications.get("smtp_port", 587)

    if not all([sender, password, receiver]):
        log.error("Email configuration is incomplete. Cannot send daily report.")
        return

    if not os.path.exists(report_path):
        log.error(f"Report file {report_path} not found. Cannot send daily report.")
        return

    try:
        msg = EmailMessage()
        msg['Subject'] = 'Network Sentinel - Daily Security Report'
        msg['From'] = sender
        msg['To'] = receiver
        
        msg.set_content(
            "Hello Network Administrator,\n\n"
            "Please find attached the daily security report from Network Sentinel.\n\n"
            "Best regards,\nNetwork Sentinel IDS"
        )

        with open(report_path, 'rb') as f:
            file_data = f.read()
            file_name = os.path.basename(report_path)
            
        msg.add_attachment(file_data, maintype='text', subtype='html', filename=file_name)

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)
        server.quit()
        
        log.info("Daily security report successfully sent via email.")
    except Exception as e:
        log.error(f"Failed to send daily email report: {e}")
