using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MVC_proj.DAL;
using MVC_proj.Models;
using MVC_proj.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private AppDbContext _context;

        public HomeController(AppDbContext context)
        {
            _context = context;
        }

        //*** Index ***//
        public IActionResult Index()
        {
            return View(new HomeIndexViewModel
            {
                Products = _context.Products.Include(p => p.Category).ToList(),
                Categories = _context.Categories.FirstOrDefault(),
                Blogs = _context.Blogs.ToList(),
                Says = _context.Says.ToList(),
                Carousels = _context.Carousels.ToList(),
                SliderImages = _context.SliderImages.ToList(),
                Sliders = _context.Sliders.FirstOrDefault()
            });
        }

        //*** Search ***//
        public async Task<IActionResult> Search(string searchedStr)
        {
            List<Carousel> carousels = _context.Carousels.ToList();

            if(string.IsNullOrWhiteSpace(searchedStr))
            {
                return PartialView("_CarouselSearchPartial", new List<Carousel>());
            }

            carousels = await _context.Carousels.Where(p => p.ImageName.ToLower().Contains(searchedStr.ToLower())).ToListAsync();
            return PartialView("_CarouselSearchPartial", carousels);
        }
    }
}
