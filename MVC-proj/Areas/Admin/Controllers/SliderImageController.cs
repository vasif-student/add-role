using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using MVC_proj.Areas.Admin.Constants;
using MVC_proj.Areas.Admin.Utilis;
using MVC_proj.Areas.Admin.ViewModels;
using MVC_proj.DAL;
using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class SliderImageController : Controller
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public SliderImageController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public async Task<IActionResult> Index()
        {
            var sliderImages = await _context.SliderImages.ToListAsync();
            return View(sliderImages);
        }

        //*** Create ***//

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(SliderImage sliderImage)
        {
            if(!ModelState.IsValid)
            {
                return View();
            }

            if (!sliderImage.File.IsSupported())
            {
                ModelState.AddModelError(nameof(sliderImage.File), "File is unsupproted");
                return View();
            }

            if (sliderImage.File.IsGreaterThanGivenSize(1024))
            {
                ModelState.AddModelError(nameof(SliderImage.File), "File size cannot be greater than 1 mb");
                return View();
            }

            sliderImage.Image = FileUtil.CreatedFile(FileConstants.ImagePath, sliderImage.File);

            await _context.SliderImages.AddAsync(sliderImage);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        //*** CreateMultipleFiles ***//

        public IActionResult CreateMultiple()
        {
            return View();
        }

        [HttpPost]
        [ActionName("CreateMultiple")]
        public async Task<IActionResult> CreateMultipleSliderImage(SliderImageCreateViewModel sliderImages)
        {
            foreach (var file in sliderImages.Files)
            {
                if(!ModelState.IsValid)
                {
                    return View();
                }
                if(!file.IsSupported())
                {
                    ModelState.AddModelError("File", $"{file.FileName} file is unsupported");
                    return View();
                }
                if(file.IsGreaterThanGivenSize(1024))
                {
                    ModelState.AddModelError(nameof(SliderImageCreateViewModel.Files), 
                        $"{file.FileName} File size is {file.Length}");
                    return View();
                }

                SliderImage sliderImage = new SliderImage();
                sliderImage.Image = FileUtil.CreatedFile(FileConstants.ImagePath, file);
                await _context.SliderImages.AddAsync(sliderImage);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        //*** Delete ***//

        public async Task<IActionResult> Delete(int id)
        {
            SliderImage sliderImage = await _context.SliderImages.FindAsync(id);
            if (sliderImage == null)
            {
                return NotFound();
            }
            return View(sliderImage);
        }

        [HttpPost]
        [ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> DeleteSliderImage(int id)
        {
            SliderImage sliderImage = await _context.SliderImages.FindAsync(id);
            if (sliderImage == null)
            {
                return NotFound();
            }
            string path = Path.Combine(FileConstants.ImagePath, sliderImage.Image);
            FileUtil.DeleteFile(path);

            _context.SliderImages.Remove(sliderImage);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        
    }
}
