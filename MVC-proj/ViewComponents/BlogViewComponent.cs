using Microsoft.AspNetCore.Mvc;
using MVC_proj.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewComponents
{
    public class BlogViewComponent : ViewComponent
    {
        private AppDbContext _context;

        public BlogViewComponent(AppDbContext context)
        {
            _context = context;
        }

        public IViewComponentResult Invoke()
        {
            return View(_context.Blogs.ToList());
        }
    }
}
