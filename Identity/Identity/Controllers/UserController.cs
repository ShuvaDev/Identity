using Identity.Data;
using Identity.Models;
using Identity.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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
        public IActionResult Index()
        {
            var users = _db.ApplicationUsers.ToList();
            var roles = _db.Roles.ToList();
            var userRoles = _db.UserRoles.ToList();

            foreach (var user in users)
            {
                var userRoleId = userRoles.FirstOrDefault(u => u.UserId == user.Id)?.RoleId;

                if (userRoleId != null)
                {
                    var roleName = roles.FirstOrDefault(r => r.Id == userRoleId)?.Name;
                    user.Role = roleName;
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
    }
}
