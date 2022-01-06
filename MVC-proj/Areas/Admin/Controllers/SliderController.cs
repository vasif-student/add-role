using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using MVC_proj.Areas.Admin.Constants;
using MVC_proj.Areas.Admin.Utilis;
using MVC_proj.DAL;
using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class SliderController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public SliderController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        public IActionResult Index()
        {
            var sliders = _context.Sliders.ToList();
            return View(sliders);
        }

        //*** Create ***//
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Slider slider)
        {
            if(!ModelState.IsValid)
            {
                return View();
            }

            if (!slider.File.IsSupported())
            {
                ModelState.AddModelError(nameof(slider.File), "File is unsupproted");
                return View();
            }

            if (slider.File.IsGreaterThanGivenSize(1024))
            {
                ModelState.AddModelError(nameof(Slider.File), "File size cannot be greater than 1 mb");
                return View();
            }

            slider.Sign = FileUtil.CreatedFile(FileConstants.ImagePath, slider.File);

            await _context.Sliders.AddAsync(slider);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
