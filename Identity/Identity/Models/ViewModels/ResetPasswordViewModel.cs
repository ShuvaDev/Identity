using Microsoft.AspNetCore.Mvc;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Identity.Models.ViewModels
{
	public class ResetPasswordViewModel
	{
		public string Code { get; set; }

		[Required]
		[DataType(DataType.EmailAddress)]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		[DataType (DataType.Password)]
		[StringLength(100, ErrorMessage = "The {0} must be at least {2} character long", MinimumLength = 6)]
		public string Password { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[DisplayName("Confirm Password")]
		[Compare("Password", ErrorMessage = "The password and confirm password don't match")]
		public string ConfirmPassword { get; set; }
	}
}
