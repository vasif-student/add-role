using Microsoft.AspNetCore.Mvc;
using MVC_proj.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewComponents
{
    public class SayViewComponent : ViewComponent
    {
        private AppDbContext _context;

        public SayViewComponent(AppDbContext context)
        {
            _context = context;
        }

        public IViewComponentResult Invoke()
        {
            return View(_context.Says.ToList());
        }
    }
}
