using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewModels
{
    public class ProductIndexViewModel
    {
        public List<Product> Products { get; set; }
        public Category Categories { get; set; }
    }
}
