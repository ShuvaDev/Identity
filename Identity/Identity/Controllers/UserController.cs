using Identity.Data;
using Identity.Models;
using Identity.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _db;
        public UserController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ApplicationDbContext db)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _db = db;
        }
        public async Task<IActionResult> Index()
        {
            var users = _db.ApplicationUsers.ToList();

            foreach (var user in users)
            {
                var user_role = await _userManager.GetRolesAsync(user) as List<String>;

                if (user_role != null)
                {
                    user.Role = string.Join(",", user_role);
                }
                else
                {
                    user.Role = "None";
                }
            }

            return View(users);
        }
        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return View("Error");
            }

            List<string> existingRoles = await _userManager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel()
            {
                User = user
            };

            foreach (var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new RoleSelection()
                {
                    RoleName = role.Name
                };
                if (existingRoles.Any(r => r == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }

            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel model)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(model.User.Id);
            if (user == null)
            {
                return View("Error");
            }
            var oldRoles = await _userManager.GetRolesAsync(user);
            var result = await _userManager.RemoveFromRolesAsync(user, oldRoles);

            if (!result.Succeeded)
            {
                TempData["Error"] = "Error While Removing Role";
                return View(model);
            }

            result = await _userManager.AddToRolesAsync(user, model.RolesList.Where(r => r.IsSelected).Select(r => r.RoleName));

            if (!result.Succeeded)
            {
                TempData["Error"] = "Error While Adding Role";
                return View(model);
            }
            TempData["Success"] = "Roles Assigned Successfully";
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return View("Error");
            }

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                // user is locked and will remain locked untill lockoutend time 
                // clicking on this action unlock them
                user.LockoutEnd = DateTime.Now;
                TempData["Success"] = "User unlocked successfully";
            }
            else
            {
                // user is not locked 
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData["Success"] = "User locked successfully";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));

        }
		// For Claim Management
		public async Task<IActionResult> ManageUserClaim(string userId)
		{
			ApplicationUser user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return View("Error");
			}

			var existingClaims = await _userManager.GetClaimsAsync(user);
			var model = new ClaimsViewModel()
			{
				User = user
			};

			foreach (Claim claim in ClaimStore.claimsList)
			{
				ClaimSelection claimSelection = new ClaimSelection()
				{
					ClaimName = claim.Type
				};
				if (existingClaims.Any(c => c.Type == claim.Type))
				{
					claimSelection.IsSelected = true;
				}
				model.ClaimsList.Add(claimSelection);
			}

			return View(model);
		}
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ManageUserClaim(ClaimsViewModel model)
		{
			ApplicationUser user = await _userManager.FindByIdAsync(model.User.Id);
			if (user == null)
			{
				return View("Error");
			}
			var oldClaims = await _userManager.GetClaimsAsync(user);
			var result = await _userManager.RemoveClaimsAsync(user, oldClaims);

			if (!result.Succeeded)
			{
				TempData["Error"] = "Error While Removing Claim";
				return View(model);
			}

			result = await _userManager.AddClaimsAsync(user, model.ClaimsList.Where(c => c.IsSelected).Select(c => new Claim(c.ClaimName, c.IsSelected.ToString())));

			if (!result.Succeeded)
			{
				TempData["Error"] = "Error While Adding Claim";
				return View(model);
			}
			TempData["Success"] = "Claim Assigned Successfully";
			return RedirectToAction(nameof(Index));
		}
	}
}
