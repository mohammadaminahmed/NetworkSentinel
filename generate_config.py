import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.config import Config

def generate_default_config():
    config = Config()
    
    # You can edit these values in config.json after running this script
    config.settings["notifications"] = {
        "telegram_enabled": False,
        "telegram_token": "YOUR_BOT_TOKEN_HERE",
        "telegram_chat_id": "YOUR_CHAT_ID_HERE",
        "email_enabled": False,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "email_sender": "your_email@gmail.com",
        "email_password": "your_app_password",
        "email_receiver": "your_email@gmail.com",
        "sound_enabled": True
    }
    
    config.save("config.json")
    print("Generated config.json successfully!")
    print("Please edit config.json to add your Telegram/Email credentials, then set '_enabled' to True.")

if __name__ == "__main__":
    generate_default_config()
