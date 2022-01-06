using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MVC_proj.Data;
using MVC_proj.Models;
using MVC_proj.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;

        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }


        //*** Login ***//

        public IActionResult Login() => View();

        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid credentials");
                return View();
            }
            var signinResult = await _signInManager.PasswordSignInAsync(user, model.Password, model.RememberMe, true);
            if (!signinResult.Succeeded)
            {
                ModelState.AddModelError("", "invalid credentials");
                return View();
            }


            return RedirectToAction("Index", "Home");
        }


        //*** Register ***//

        public IActionResult Register() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if(!ModelState.IsValid)
            {
                return View();
            }

            var dbUser = await _userManager.FindByNameAsync(model.UserName);

            if(dbUser != null)
            {
                ModelState.AddModelError(nameof(RegisterViewModel.UserName),
                    "The user with this username is already exist");
                return View();
            }

            User user = new User
            {
                FullName = model.FullName,
                UserName = model.UserName,
                Email = model.Email
            };

            var identityResult = await _userManager.CreateAsync(user, model.Password);
            if(!identityResult.Succeeded)
            {
                foreach (var item in identityResult.Errors)
                {
                    ModelState.AddModelError("", item.Description);
                }
                return View();
            }

            await _signInManager.SignInAsync(user, true);
            await _userManager.AddToRoleAsync(user, RoleConstants.User);

            return RedirectToAction("Index", "Home");
        }

        //*** Logout ***//
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
