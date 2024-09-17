using Identity.Models;
using Identity.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Identity.Controllers
{
	public class AccountController : Controller
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly IEmailSender _emailSender;
		private readonly UrlEncoder _urlEncoder;
		public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IEmailSender emailSender, UrlEncoder urlEncoder)
		{
			_signInManager = signInManager;
			_userManager = userManager;
			_roleManager = roleManager;
			_emailSender = emailSender;
			_urlEncoder = urlEncoder;
		}
		public async Task<IActionResult> Register(string? returnurl = null)
		{
			if(!_roleManager.RoleExistsAsync(SD.Admin).GetAwaiter().GetResult())
			{
				await _roleManager.CreateAsync(new IdentityRole(SD.Admin));
				await _roleManager.CreateAsync(new IdentityRole(SD.User));
			}

			RegisterViewModel registerViewModel = new() {
				RoleList = _roleManager.Roles.Select(r => r.Name).Select(r => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem()
				{
					Text = r,
					Value = r
				})
			};

			ViewData["ReturnUrl"] = returnurl;

			return View(registerViewModel);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string? returnurl = null)
		{
			returnurl = returnurl ?? Url.Content("~/");

			if (ModelState.IsValid)
			{
				var user = new ApplicationUser()
				{
					UserName = registerViewModel.Email,
					Email = registerViewModel.Email,
					Name = registerViewModel.Name,
					DateCreated = DateTime.Now
				};
				var result = await _userManager.CreateAsync(user, registerViewModel.Password);
				if (result.Succeeded)
				{
					var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
					var callbackUrl = Url.Action("ConfirmEmail", "Account", new
					{
						userid = user.Id,
						code
					}, protocol: HttpContext.Request.Scheme);
					// await _emailSender.SendEmailAsync(registerViewModel.Email, "Confirm Email", $"Please confirm your email by clicking here - <a href='{callbackUrl}'>Link</a>");
                    
					// ToDo : মেইল কনফার্মশেন মেসেজ পাঠানোর পরে ইউজারকে কনফার্ম করতে বলার জন্য ভিউ বানাতে হবে।
                    //      : মেইন কনফার্মশেন না হলে লগিন করতে দেওয়া যাবে না।
                    
					if(registerViewModel.RoleSelect != null)
					{
						await _userManager.AddToRoleAsync(user, registerViewModel.RoleSelect);
					}
					else
					{
						await _userManager.AddToRoleAsync(user, SD.User);
					}

					await _signInManager.SignInAsync(user, isPersistent: false);
					return LocalRedirect(returnurl);
				}
				else
				{
					foreach (IdentityError error in result.Errors)
					{
						ModelState.AddModelError(string.Empty, error.Description);
					}
				}
			}
			registerViewModel.RoleList = _roleManager.Roles.Select(r => r.Name).Select(r => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem()
			{
				Text = r,
				Value = r
			});

			return View(registerViewModel);
		}

		public async Task<IActionResult> ConfirmEmail(string code, string userId)
		{
			var user = await _userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return View("Error");
			}
			var result = await _userManager.ConfirmEmailAsync(user, code);
			if (result.Succeeded)
			{
				return View();
			}
			else
			{
				return View("Error");
			}
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Logout()
		{
			await _signInManager.SignOutAsync();
			return RedirectToAction("Index", "Home");
		}

		public IActionResult Login(string? returnurl = null)
		{
			ViewData["ReturnUrl"] = returnurl;
			return View();
		}
		[HttpPost]
		public async Task<IActionResult> Login(LoginViewModel loginViewModel, string? returnurl)
		{
			returnurl = returnurl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, isPersistent: loginViewModel.RememberMe, lockoutOnFailure: true);
				if (result.Succeeded)
				{
					return LocalRedirect(returnurl);
				}
				if (result.RequiresTwoFactor)
				{
					return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl, loginViewModel.RememberMe });
				}
				if (result.IsLockedOut)
				{
					return View("Lockout");
				}
				else
				{
					ModelState.AddModelError(string.Empty, "Invalid Login Attempt");
					return View(loginViewModel);
				}
			}

			return View(loginViewModel);
		}



		public IActionResult ForgotPassword()
		{
			return View();
		}
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel forgotPasswordViewModel)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(forgotPasswordViewModel.Email);

				if (user == null)
				{
					return RedirectToAction("ForgotPasswordConfirmation");
				}
				var code = await _userManager.GeneratePasswordResetTokenAsync(user);
				var callbackUrl = Url.Action("ResetPassword", "Account", new
				{
					userid = user.Id,
					code
				}, protocol: HttpContext.Request.Scheme);
				await _emailSender.SendEmailAsync(forgotPasswordViewModel.Email, "Reset Password", $"Please reset your password by clicking here - <a href='{callbackUrl}'>Link</a>");

				return RedirectToAction("ForgotPasswordConfirmation");
			}
			return View(forgotPasswordViewModel);
		}

		public IActionResult ForgotPasswordConfirmation()
		{
			return View();
		}
		public IActionResult ResetPassword(string? code)
		{
			ResetPasswordViewModel model = new() { Code = code };
			return View(model);
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.Email);
				if (user == null)
				{
					return RedirectToAction("ResetPasswordConfirmation");
				}
				var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
				if (result.Succeeded)
				{
					return RedirectToAction("ResetPasswordConfirmation");
				}
				else
				{
					foreach (IdentityError error in result.Errors)
					{
						ModelState.AddModelError(string.Empty, error.Description);
					}
				}
			}
			return View();
		}
		public IActionResult ResetPasswordConfirmation()
		{
			return View();
		}

		public async Task<IActionResult> IsEmailAlreadyRegisterd(string email)
		{
			ApplicationUser user = await _userManager.FindByEmailAsync(email);
			if (user == null)
			{
				return Json(true);
			}
			else
			{
				return Json(false);
			}
		}
        public IActionResult Error()
        {
            return View();
        }
        public IActionResult NoAccess()
        {
            return View();
        }
        // For two factor authentication
        [Authorize]
		public async Task<IActionResult> EnableAuthenticator()
		{
			string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}";
			var user = await _userManager.GetUserAsync(User);
			await _userManager.ResetAuthenticatorKeyAsync(user);

			var token = await _userManager.GetAuthenticatorKeyAsync(user);

			// IdentityManger will be title in apps
			string authUri = string.Format(authenticatorUriFormat, _urlEncoder.Encode("IdentityManger"), _urlEncoder.Encode(user.Email), token);

			var model = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUrl = authUri };
			return View(model);
		}

		[Authorize]
		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.GetUserAsync(User);
				var succeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
				if (succeded)
				{
					await _userManager.SetTwoFactorEnabledAsync(user, true);
				}
				else
				{
					ModelState.AddModelError("Verify", "Your two factor auth code could not be validated!");
					return View(model);
				}
				return RedirectToAction("AuthenticatorConfirmation");
			}
			return View("Error");
		}
		[Authorize]
		public IActionResult AuthenticatorConfirmation()
		{
			return View();
		}

		[Authorize]
		public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
		{
			var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
			if (user == null)
			{
				return View("Error");
			}
			ViewData["ReturnUrl"] = returnUrl;

			return View(new VerifyAuthenticatorViewModel() { ReturnUrl = returnUrl, RememberMe = rememberMe });
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		[Authorize]
		public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
		{
			model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
			if(!ModelState.IsValid)
			{
				return View(model);
			}

			var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient : false);
			if(result.Succeeded)
			{
				return LocalRedirect(model.ReturnUrl);
			}
			if(result.IsLockedOut)
			{
				return View("Lockout");
			}
			else
			{
				ModelState.AddModelError(string.Empty, "Invalid login attempt");
				return View(model);
			}
		}

		[Authorize]
		public async Task<IActionResult> RemoveAuthenticator()
		{
			var user = await _userManager.GetUserAsync(User);
			await _userManager.ResetAuthenticatorKeyAsync(user);
			await _userManager.SetTwoFactorEnabledAsync(user, false);

			return RedirectToAction(nameof(Index), "Home");
		}

		// For external login
		[HttpPost]
		[ValidateAntiForgeryToken]
		public IActionResult ExternalLogin(string provider, string? returnUrl = null)
		{
			var redirectUrl = Url.Action("ExternalLoginCallback", "Account", new { returnUrl });
			var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

			return Challenge(properties, provider);
		}

		public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
		{
			returnUrl = returnUrl ?? Url.Content("~/");
			if(remoteError != null)
			{
				ModelState.AddModelError(string.Empty, $"Error from external provider - {remoteError}");
				return View(nameof(Login));
			}

			var info = await _signInManager.GetExternalLoginInfoAsync();
			if(info == null)
			{
				return RedirectToAction(nameof(Login));
			}

			// sign in the user with external login provider. only if they have a login
			var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

			if (result.Succeeded)
			{
				await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
				return LocalRedirect(returnUrl);
			}
			if (result.RequiresTwoFactor)
			{
				return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnurl = returnUrl });
			}
			else
			{
				// that means user account is not create and we will display a view to create account.
				ViewData["ReturnUrl"] = returnUrl;
				ViewData["ProviderDisplayName"] = info.ProviderDisplayName;

				return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel()
				{
					Name = info.Principal.FindFirstValue(ClaimTypes.Name),
					Email = info.Principal.FindFirstValue(ClaimTypes.Email)
				});
			}
		}

		[HttpPost]
		[ValidateAntiForgeryToken]

		public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model,string? returnurl = null)
		{
			returnurl = returnurl ?? Url.Content("~/");
			if (ModelState.IsValid)
			{
				var info = await _signInManager.GetExternalLoginInfoAsync();
				if(info == null)
				{
					return View("Error");
				}

				var user = new ApplicationUser()
				{
					UserName = model.Email,
					Email = model.Email,
					Name = model.Name,
					NormalizedEmail = model.Email.ToUpper(),
					DateCreated = DateTime.Now
				};

				var result = await _userManager.CreateAsync(user);
				if (result.Succeeded)
				{
					await _userManager.AddToRoleAsync(user, SD.User);

					result = await _userManager.AddLoginAsync(user, info);

					if(result.Succeeded)
					{
						await _signInManager.SignInAsync(user, isPersistent: false);
						await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
					}

					return LocalRedirect(returnurl);
				}
				else
				{
					foreach (IdentityError error in result.Errors)
					{
						ModelState.AddModelError(string.Empty, error.Description);
					}
				}
			}
			ViewData["ReturnUrl"] = returnurl;
			return View(model);
		}

	}
}
