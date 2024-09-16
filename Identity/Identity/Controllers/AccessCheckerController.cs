using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
	[Authorize]
	public class AccessCheckerController : Controller
	{
		[AllowAnonymous]
		// Anyone can access this
		public IActionResult AllAccess()
		{
			return View();
		}

		// Anyone that has logged in can acccess
		public IActionResult AuthorizedAccess()
		{
			return View();
		}

		[Authorize(Roles = $"{SD.Admin}, {SD.User}")]
		// Anyone with role of user or admin can acccess
		public IActionResult UserOrAdminRoleAccess()
		{
			return View();
		}

		// Anyone with role of user and admin can acccess
		[Authorize(Policy = "AdminAndUser")]
        public IActionResult UserAndAdminRoleAccess()
        {
            return View();
        }

        //[Authorize(Roles = $"{SD.Admin}")]
        [Authorize(Policy = "Admin")]
		// Anyone with role of admin can acccess
		public IActionResult AdminRoleAccess()
		{
			return View();
		}

		[Authorize(Policy = "AdminRole_CreateClaim")]
		// Anyone with admin role and create claim can acccess
		public IActionResult Admin_CreateAccess()
		{
			return View();
		}

        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim")]
        // Anyone with admin role and (create, edit, delete) claim can acccess
        public IActionResult Admin_Create_Edit_DeleteAccess()
		{
			return View();
		}

        [Authorize(Policy = "AdminRole_CreateEditDeleteClaim_OrSuperAdminRole")]
        public IActionResult Admin_Create_Edit_DeleteAccess_or_SuperAdminRole()
        {
            return View();
        }

		[Authorize(Policy = "AdminWithMoreThan1000Days")]

		public IActionResult OnlyShuva()
		{
			return View();
		}
    }
}
