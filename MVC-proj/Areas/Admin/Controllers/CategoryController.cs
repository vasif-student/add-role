using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MVC_proj.DAL;
using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class CategoryController : Controller
    {
        private readonly AppDbContext _context;

        public CategoryController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            var categories = await _context.Categories.ToListAsync();
            return View(categories);
        }

        //*** Detail ***//
        public async Task<IActionResult> Detail(int id)
        {
            var category = await _context.Categories.FindAsync(id);

            if(category == null)
            {
                return NotFound();
            }

            return View(category);
        }

        //*** Create ***//
        public async Task<IActionResult> Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Category category)
        {
            if(!ModelState.IsValid)
            {
                return View();
            }
            await _context.Categories.AddAsync(category);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        //*** Update ***//
        public async Task<IActionResult> Update(int id)
        {
            Category category = await _context.Categories.FindAsync(id);

            if(category == null)
            {
                return NotFound();
            }

            return View(category);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task <IActionResult> Update (int id, Category category)
        {
            if(!ModelState.IsValid)
            {
                return View(category);
            }

            if(id != category.Id)
            {
                return BadRequest();
            }

            bool isExist = await _context.Categories.AnyAsync(c => c.Id == id);

            if(!isExist)
            {
                return NotFound();
            }

            _context.Update(category);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        //*** Delete ***//
        public async Task<IActionResult> Delete(int id)
        {
            Category category = await _context.Categories.FindAsync(id);
            if(category == null)
            {
                return NotFound();
            }
            return View(category);
        }

        [HttpPost]
        [ActionName("Delete")]
        [ValidateAntiForgeryToken]

        public async Task<IActionResult> DeleteCategory(int id)
        {
            Category category = await _context.Categories.FindAsync(id);
            if(category == null)
            {
                return NotFound();
            }
            _context.Categories.Remove(category);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        //*** Search ***//

        public async Task<IActionResult> Search(string searchedCategory)
        {
            List<Category> categories = await _context.Categories.ToListAsync();

            if(string.IsNullOrWhiteSpace(searchedCategory))
            {
                return PartialView("_CategorySearchPartial", new List<Category>());
            }

            categories = await _context.Categories.Where(c => c.Name.ToLower().Contains(searchedCategory.ToLower())).ToListAsync();
            return PartialView("_CategorySearchPartial", categories);
        }

    }
}
