using Identity.Data;
using Identity.Services.IServices;

namespace Identity.Services
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _db;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _db = db;
        }
        public int Get(string userId)
        {
            var user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(user != null && user.DateCreated != DateTime.MinValue)
            {
                return (user.DateCreated - DateTime.Now).Days;
            }
            return 0;
        }
    }
}
