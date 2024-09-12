using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Identity.Models.ViewModels
{
	public class LoginViewModel
	{
		[Required]
		[DataType(DataType.EmailAddress)]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		[DataType (DataType.Password)]
		public string Password { get; set; }

		[DisplayName("Remember Me?")]
		public bool RememberMe { get; set; }
	}
}
