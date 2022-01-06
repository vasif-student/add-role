using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
    public class LayoutController : Controller
    {

        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public LayoutController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }
        public async Task<IActionResult> Index()
        {
            var layouts = await _context.Layouts.ToListAsync();
            return View(layouts);
        }

        public async Task<IActionResult> Detail(int id)
        {
            var layout = await _context.Layouts.FindAsync(id);
            if(layout == null)
            {
                return NotFound();
            }

            return View(layout);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Layout layout)
        {
            if(!ModelState.IsValid)
            {
                return View();
            }

            
            if (!layout.File.ContentType.Contains("image"))
            {
                ModelState.AddModelError(nameof(Layout.File), "File is unsupproted");
                return View();
            }

            if (layout.File.Length > 1024 * 1000)
            {
                ModelState.AddModelError(nameof(Layout.File), "File size cannot be greater than 1 mb");
                return View();
            }

            string fileName = Guid.NewGuid() + layout.File.FileName;
            string wwwRootPath = _env.WebRootPath;

            var path = Path.Combine(wwwRootPath, "img", fileName);
            FileStream stream = new FileStream(path, FileMode.Create);
            await layout.File.CopyToAsync(stream);
            stream.Close();

            layout.Image = fileName;

            await _context.Layouts.AddAsync(layout);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));

        }

        public async Task<IActionResult> Delete(int id)
        {
            Layout layout = await _context.Layouts.FindAsync(id);
            if(layout == null)
            {
                return NotFound();
            }
            return View(layout);
        }

        [HttpPost]
        [ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> DeleteLayout(int id)
        {
            Layout layout = await _context.Layouts.FindAsync(id);
            if(layout == null)
            {
                return NotFound();
            }
            _context.Layouts.Remove(layout);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
    }
}
