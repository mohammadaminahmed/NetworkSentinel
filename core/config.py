import json
import os
from core.logger import log

class Config:
    def __init__(self):
        self.settings = {
            "interface": "auto",
            "log_level": "INFO",
            "alert_threshold": 5,
            "daily_report_time": "23:59",
            "notifications": {
                "telegram_enabled": False,
                "telegram_token": "",
                "telegram_chat_id": "",
                "email_enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "email_sender": "",
                "email_password": "",
                "email_receiver": "",
                "sound_enabled": True
            },
            "ips_enabled": True
        }

    def load(self, path: str):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.settings.update(json.load(f))
            except Exception as e:
                log.error(f"Failed to load config: {e}")

    def save(self, path: str):
        try:
            with open(path, 'w') as f:
                json.dump(self.settings, f, indent=4)
        except Exception as e:
            log.error(f"Failed to save config: {e}")
