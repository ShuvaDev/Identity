using Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    public class RoleController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(ApplicationDbContext db, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();
            return View(roles);
        }
        
        public IActionResult Upsert(string roleId)
        {
            if(string.IsNullOrEmpty(roleId))
            {
                // Create
                return View();
            }
            else
            {
                // Update
                var objFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleId);
                return View(objFromDb);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
		public async Task<IActionResult> Upsert(IdentityRole roleObj)
		{
			if(await _roleManager.RoleExistsAsync(roleObj.Name))
            {
				// error
				TempData["Error"] = "Role already exists!";
				return RedirectToAction(nameof(Index));
			}

			if (string.IsNullOrEmpty(roleObj.NormalizedName))
			{
				// Create
                await _roleManager.CreateAsync(new IdentityRole { Name = roleObj.Name });
                TempData["Success"] = "Role created successfully!";
			}
			else
			{
				// Update
				var objFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleObj.Id);
                objFromDb.Name = roleObj.Name;
                objFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objFromDb);
				TempData["Success"] = "Role updated successfully!";
			}
            return RedirectToAction(nameof(Index));
		}

        public async Task<IActionResult> Delete(string roleId)
        {
            if(_db.UserRoles.FirstOrDefault(r => r.RoleId == roleId) == null)
            {
			    var objFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleId);
                if (objFromDb != null)
                {
                    await _roleManager.DeleteAsync(objFromDb);
					TempData["Success"] = "Role deleted successfully!";
				}
            }
            else
            {
				// Role can't be delete. Because it is already assigned to a user
				TempData["Error"] = "Role can't be delete!";
			}
			return RedirectToAction(nameof(Index));
		}
	}
}
