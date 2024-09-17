using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Identity.Models.ViewModels
{
	public class ExternalLoginConfirmationViewModel
	{
		[Required]
		public string Name { get; set; }

		[Required]
		[DataType(DataType.EmailAddress)]
		[EmailAddress]
		public string Email { get; set; }

	}
}
