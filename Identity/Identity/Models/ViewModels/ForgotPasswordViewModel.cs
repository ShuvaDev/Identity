using System.ComponentModel.DataAnnotations;

namespace Identity.Models.ViewModels
{
	public class ForgotPasswordViewModel
	{
		[Required]
		[EmailAddress]
		public string Email { get; set; }
	}
}
