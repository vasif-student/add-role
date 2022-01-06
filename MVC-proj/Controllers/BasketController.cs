using Microsoft.AspNetCore.Mvc;
using MVC_proj.DAL;
using MVC_proj.Models;
using MVC_proj.ViewModels;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Controllers
{
    public class BasketController : Controller
    {
        private readonly AppDbContext _context;

        public BasketController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> AddToBasket(int id)
        {
            Product product = await _context.Products.FindAsync(id);

            List<BasketViewModel> basket;

            var basketJson = Request.Cookies["basket"];

            if (string.IsNullOrEmpty(basketJson))
            {
                basket = new List<BasketViewModel>();
            }
            else
            {
                basket = JsonConvert.DeserializeObject<List<BasketViewModel>>(basketJson);
            }

            BasketViewModel existProduct = basket.Find(p => p.Id == id);
            if (existProduct == null)
            {
                BasketViewModel basketViewModel = new BasketViewModel();
                basketViewModel.Id = product.Id;
                basketViewModel.Name = product.Name;
                basketViewModel.Price = product.Price;
                basketViewModel.Category = product.Category;

                basket.Add(basketViewModel);
            }
            else
            {
                existProduct.Count++;
            }


            Response.Cookies.Append("basket", JsonConvert.SerializeObject(basket));

            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> GetBasket()
        {
            List<BasketViewModel> basket = JsonConvert.DeserializeObject<List<BasketViewModel>>(Request.Cookies["basket"]);

            var newBasket = new List<BasketViewModel>();

            foreach (var item in basket)
            {
                Product product = await _context.Products.FindAsync(item.Id);
                if(product == null)
                {
                    continue;
                }

                item.Price = product.Price;
                item.Name = product.Name;
            }

            var json = JsonConvert.SerializeObject(basket);
            Response.Cookies.Append("basket", json);


            return Content(json);
        }
    }
}
