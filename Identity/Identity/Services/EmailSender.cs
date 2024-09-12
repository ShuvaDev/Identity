using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace Identity.Services
{
	public class EmailSender : IEmailSender
	{
		public string SendGridKey { get; set; }
		public EmailSender(IConfiguration config)
		{
			SendGridKey = config.GetValue<string>("SendGrid:SecretKey");
		}
		public Task SendEmailAsync(string email, string subject, string htmlMessage)
		{
			var client = new SendGridClient(SendGridKey);
			var from_email = new EmailAddress("test@gmail.com", "Test");
			var to_email = new EmailAddress(email);
			var msg = MailHelper.CreateSingleEmail(from_email, to_email, subject, "", htmlMessage);
			
			return client.SendEmailAsync(msg);
		}
	}
}
