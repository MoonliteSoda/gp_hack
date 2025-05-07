import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from service.models.email_data import EmailData

from utils.logger import get_logger
from utils.config import CONFIG

log = get_logger("EmailService")


class EmailService:
    def __init__(self):
        self.smtp_server = CONFIG.email.smtp_server
        self.smtp_port = CONFIG.email.smtp_port
        self.smtp_username = CONFIG.email.smtp_username
        self.smtp_password = CONFIG.email.smtp_password
        self.sender_email = CONFIG.email.sender_email # TODO сделать закрытой переменой

    async def send_email(self,
                         email_data: EmailData) -> bool:
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = ", ".join(email_data.recipients)
            msg['Subject'] = email_data.subject

            if email_data.cc:
                msg['Cc'] = ", ".join(email_data.cc)
            if email_data.bcc:
                msg['Bcc'] = ", ".join(email_data.bcc)

            html_content = email_data.template.value.render(
                subject=email_data.subject,
                message=email_data.message
            )

            msg.attach(MIMEText(html_content, 'html'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)

                all_recipients = email_data.recipients.copy()
                if email_data.cc:
                    all_recipients.extend(email_data.cc)
                if email_data.bcc:
                    all_recipients.extend(email_data.bcc)

                server.sendmail(self.sender_email, all_recipients, msg.as_string())

            log.info(f"Email sent successfully to {', '.join(email_data.recipients)}")

        except Exception as e:
            log.error(f"Failed to send emails: {", ".join(email_data.recipients)} \nwith error: {str(e)}", exc_info=True)

# async def main():
#     email_service = EmailService()
#     await email_service.send_email(EmailData(message="Привет", template=EmailTemplates.DEFAULT_MESSAGE, subject="Тест",
#                                          recipients=["oleg.gerbylev@gmail.com"]))
#
# if __name__ == "__main__":
#     asyncio.run(main())