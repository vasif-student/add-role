using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MVC_proj.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.DAL
{
    public class DataInitializer
    {
        private readonly AppDbContext _dbContext;
        private readonly RoleManager<IdentityRole> _roleManager;

        public DataInitializer(AppDbContext dbContext, RoleManager<IdentityRole> roleManager)
        {
            _dbContext = dbContext;
            _roleManager = roleManager;
        }

        public async Task SeedData()
        {
            if(!_dbContext.Roles.Any())
            {
                await _roleManager.CreateAsync(new IdentityRole(RoleConstants.Admin));
                await _roleManager.CreateAsync(new IdentityRole(RoleConstants.Moderator));
                await _roleManager.CreateAsync(new IdentityRole(RoleConstants.User));
            }
        }
    }
}
