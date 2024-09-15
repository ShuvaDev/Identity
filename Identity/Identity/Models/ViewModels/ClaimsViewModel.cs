namespace Identity.Models.ViewModels
{
	public class ClaimsViewModel
	{
		public ClaimsViewModel() 
		{
			ClaimsList = [];
		}
		public ApplicationUser User { get; set; }
		public List<ClaimSelection> ClaimsList { get; set; }

	}
	public class ClaimSelection
	{
		public string ClaimName { get; set; }
		public bool IsSelected { get; set; }
	}
}
