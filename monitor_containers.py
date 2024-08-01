import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings

def check_containers():
    try:
        result = subprocess.run(['docker', 'ps', '-a'], capture_output=True, text=True)
        print("result : ", result)
        if 'Exited' in result.stdout:
            send_email('Docker Container Alert', 'One or more Docker containers have exited.')
    except Exception as e:
        send_email('Docker Monitoring Error', str(e))

def send_email(subject, message):
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [settings.ADMIN_EMAIL,settings.ORG_ADMIN_EMAIL]
    msg = MIMEMultipart()
    msg['From'] = email_from
    msg['To'] = ", ".join(recipient_list)
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))

    try:
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()
        server.login(email_from, settings.EMAIL_HOST_PASSWORD)
        text = msg.as_string()
        server.sendmail(email_from, recipient_list, text)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

if __name__ == '__main__':
    check_containers()
