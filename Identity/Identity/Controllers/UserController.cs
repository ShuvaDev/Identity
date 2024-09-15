using Identity.Data;
using Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    public class UserController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;
        public UserController(UserManager<ApplicationUser> userManager, ApplicationDbContext db)
        {
            _userManager = userManager;
            _db = db;
        }
        public IActionResult Index()
        {
            var users = _db.ApplicationUsers.ToList();
            var roles = _db.Roles.ToList();
            var userRoles = _db.UserRoles.ToList();

            foreach(var user in users)
            {
                var userRoleId = userRoles.FirstOrDefault(u => u.UserId == user.Id)?.RoleId;

                if(userRoleId != null)
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
    }
}
