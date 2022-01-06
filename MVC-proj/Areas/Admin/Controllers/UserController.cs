using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MVC_proj.Areas.Admin.ViewModels;
using MVC_proj.DAL;
using MVC_proj.Data;
using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class UserController : Controller
    {

        private readonly AppDbContext _dbContext;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(AppDbContext dbContext, UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
        {
            _dbContext = dbContext;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Index()
        {
            var users = await _dbContext.Users.ToListAsync();
            var userList = new List<UserViewModel>();

            foreach (var user in users)
            {
                userList.Add(new UserViewModel
                {
                    Id = user.Id,
                    FullName = user.FullName,
                    UserName = user.UserName,
                    Email = user.Email,
                    Role = (await _userManager.GetRolesAsync(user))[0]
                });
            }

            return View(userList);
        }

        //***** Add Role *****//

        public async Task<IActionResult> AddRole(string id)
        {
            var user = await _dbContext.Users.FindAsync(id);

            if(user == null)
            {
                return NotFound();
            }

            List<string> roles = new List<string>() { RoleConstants.Admin, RoleConstants.Moderator, RoleConstants.User };

            return View(roles.ToList());

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddRole(string id, string role)
        {
            var user = await _dbContext.Users.FindAsync(id);

            await _userManager.AddToRoleAsync(user, role);

            return RedirectToAction(nameof(Index));

        }

        //***** Change Password *****//

        public async Task<IActionResult> ChangePassword(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var changePasswordViewModel = new ChangePasswordViewModel
            {
                Id = user.Id,
                Username = user.UserName
            };
            return View(changePasswordViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(string id, ChangePasswordViewModel model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            var changePasswordViewModel = new ChangePasswordViewModel
            {
                Id = user.Id,
                Username = user.UserName
            };

            if (!ModelState.IsValid)
            {
                return View();
            }

            if(!await _userManager.CheckPasswordAsync(user,model.OldPassword))
            {
                ModelState.AddModelError(nameof(ChangePasswordViewModel.OldPassword), "Old password is incorrect");
                return View(changePasswordViewModel);
            }

            var identityResult = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);

            if(!identityResult.Succeeded)
            {
                foreach (var error in identityResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
                return View();
            }

            return RedirectToAction("Index", "User", new { area = "Admin" });
        }
    }
}
