using Microsoft.AspNetCore.Mvc;
using MVC_proj.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewComponents
{
    public class FooterViewComponent : ViewComponent
    {
        private AppDbContext _context;

        public FooterViewComponent(AppDbContext context)
        {
            _context = context;
        }

        public IViewComponentResult Invoke()
        {
            return View(_context.Layouts.FirstOrDefault());
        }
    }
}
