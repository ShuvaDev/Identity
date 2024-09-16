using Identity;
using Identity.Authorize;
using Identity.Data;
using Identity.Models;
using Identity.Services;
using Identity.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
	options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
	.AddEntityFrameworkStores<ApplicationDbContext>()
	.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
	options.AccessDeniedPath = "/Account/NoAccess";
});
builder.Services.Configure<IdentityOptions>(options =>
{
	options.Password.RequireUppercase = false;
	options.Lockout.MaxFailedAccessAttempts = 3;
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
	options.SignIn.RequireConfirmedEmail = false;
});
builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("Admin", policy => policy.RequireRole(SD.Admin));
	options.AddPolicy("AdminAndUser", policy => policy.RequireRole(SD.Admin).RequireRole(SD.User));
	options.AddPolicy("AdminRole_CreateClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create", "True"));
	options.AddPolicy("AdminRole_CreateEditDeleteClaim", policy => policy.RequireRole(SD.Admin).RequireClaim("create", "True").RequireClaim("edit", "True").RequireClaim("delete", "True"));
	
	options.AddPolicy("AdminRole_CreateEditDeleteClaim_OrSuperAdminRole", policy => policy.RequireAssertion(context => (
		context.User.IsInRole(SD.Admin) &&
		context.User.HasClaim(c => c.Type == "Create" && c.Value == "True") &&
		context.User.HasClaim(c => c.Type == "Edit" && c.Value == "True") &&
		context.User.HasClaim(c => c.Type == "Delete" && c.Value == "True") 
	) ||
		context.User.IsInRole(SD.SuperAdmin)
	));

	// Custom policy
	options.AddPolicy("OnlySuperAdminChecker", policy => policy.Requirements.Add(new OnlySuperAdminChecker()));
	options.AddPolicy("AdminWithMoreThan1000Days", policy => policy.Requirements.Add(new AdminWithMoreThan1000DaysRequirement(1000)));

	
});

builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
// handler এবং requirement একেই ক্লাসে না হওয়ার কারণে নিচের স্টেটমেন্ট এড করতে হয়েছে।
builder.Services.AddScoped<IAuthorizationHandler, AdminWith1000DaysOverHandler>();

builder.Services.AddTransient<IEmailSender, EmailSender>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
}
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
