EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",  # For Gmail
    "smtp_port": 587,
    "sender_email": "tahaomrani@aiesec.net",  # Replace with your email
    "sender_password": "gwcwcjzdspbklxmx",  # Corrected App Password without spaces
    "recipient_email": "omranitaha26@gmail.com"  # Replace with recipient email
}

# Email notification settings
EMAIL_SETTINGS = {
    "enabled": True,
    "cooldown_minutes": 5,  # Don't send emails more frequently than this
    "max_emails_per_hour": 10  # Maximum emails per hour to prevent spam
}