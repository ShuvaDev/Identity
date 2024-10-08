﻿using Identity.Models;
using Identity.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
	public class AccountController : Controller
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly IEmailSender _emailSender;
		public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IEmailSender emailSender)
		{
			_signInManager = signInManager;
			_userManager = userManager;
			_emailSender = emailSender;
		}
		public IActionResult Register(string? returnurl = null)
		{
			@ViewData["ReturnUrl"] = returnurl;
			RegisterViewModel registerViewModel = new();
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
				};
				var result = await _userManager.CreateAsync(user, registerViewModel.Password);
				if(result.Succeeded)
				{
					var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
					var callbackUrl = Url.Action("ConfirmEmail", "Account", new
					{
						userid = user.Id,
						code
					}, protocol: HttpContext.Request.Scheme);
					await _emailSender.SendEmailAsync(registerViewModel.Email, "Confirm Email", $"Please confirm your email by clicking here - <a href='{callbackUrl}'>Link</a>");


					await _signInManager.SignInAsync(user, isPersistent: false);
					return LocalRedirect(returnurl);
				}
				else
				{
					foreach(IdentityError error in result.Errors)
					{
						ModelState.AddModelError(string.Empty, error.Description);
					}
				}
			}

			return View(registerViewModel);
		}

		public async Task<IActionResult> ConfirmEmail(string code, string userId)
		{
			var user = await _userManager.FindByIdAsync(userId);
			if(user == null)
			{
				return View("Error");
			}
			var result = await _userManager.ConfirmEmailAsync(user, code);
			if(result.Succeeded)
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
			if(ModelState.IsValid)
			{
				var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, isPersistent: loginViewModel.RememberMe, lockoutOnFailure: true);
				if(result.Succeeded)
				{
					return LocalRedirect(returnurl);
				}
				if(result.IsLockedOut)
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
			if(ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(forgotPasswordViewModel.Email);

				if(user == null)
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
				if(result.Succeeded)
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
			if(user == null)
			{
				return Json(true);
			}
			else
			{
				return Json(false);
			}
		}
	}
}
