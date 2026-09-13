import urllib.request
import urllib.parse
import json
import smtplib
from email.mime.text import MIMEText
import threading
from core.logger import log
import sys
import os

def play_alarm():
    """Play a sound alarm cross-platform."""
    try:
        if sys.platform == 'win32':
            import winsound
            # Play a Beep at 2500 Hz for 1000 milliseconds
            winsound.Beep(2500, 1000)
        else:
            # ANSI bell character for Linux/Mac
            print('\a', end='', flush=True)
    except Exception as e:
        log.error(f"Failed to play alarm sound: {e}")

def _send_telegram_async(message: str, token: str, chat_id: str):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({'chat_id': chat_id, 'text': message}).encode('utf-8')
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                log.error(f"Telegram failed with status {response.status}")
    except Exception as e:
        log.error(f"Failed to send Telegram notification: {e}")

def send_telegram(message: str, config: dict):
    token = config.get("telegram_token")
    chat_id = config.get("telegram_chat_id")
    if token and chat_id:
        threading.Thread(target=_send_telegram_async, args=(message, token, chat_id), daemon=True).start()

def _send_email_async(message: str, config: dict):
    try:
        server = config.get("smtp_server", "smtp.gmail.com")
        port = config.get("smtp_port", 587)
        sender = config.get("email_sender")
        password = config.get("email_password")
        receiver = config.get("email_receiver")

        if not all([sender, password, receiver]):
            return

        msg = MIMEText(message)
        msg['Subject'] = '🚨 Network Sentinel Alert'
        msg['From'] = sender
        msg['To'] = receiver

        with smtplib.SMTP(server, port) as smtp:
            smtp.starttls()
            smtp.login(sender, password)
            smtp.send_message(msg)
    except Exception as e:
        log.error(f"Failed to send Email notification: {e}")

def send_email(message: str, config: dict):
    if config.get("email_sender"):
        threading.Thread(target=_send_email_async, args=(message, config), daemon=True).start()

def notify(severity: str, title: str, description: str, config: dict):
    """Main function to trigger notifications based on config."""
    # Play sound only for HIGH or CRITICAL alerts
    if config.get("sound_enabled", True) and severity in ["HIGH", "CRITICAL"]:
        threading.Thread(target=play_alarm, daemon=True).start()

    message = f"🚨 *{severity} ALERT*\n\n*Title:* {title}\n*Details:* {description}"
    
    if config.get("telegram_enabled"):
        send_telegram(message, config)
        
    if config.get("email_enabled"):
        send_email(message, config)
