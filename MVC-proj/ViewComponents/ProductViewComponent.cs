using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MVC_proj.DAL;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewComponents
{
    public class ProductViewComponent : ViewComponent
    {
        private AppDbContext _context;

        public ProductViewComponent(AppDbContext context)
        {
            _context = context;
        }

        public IViewComponentResult Invoke()
        {
            var products = _context.Products.Include(p => p.Category).ToList();
            return View(products);
        }
    }
}
