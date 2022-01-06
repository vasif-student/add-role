using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.ViewModels
{
    public class HomeIndexViewModel
    {
        public List<Product> Products { get; set; }
        public Category Categories { get; set; }
        public List<Blog> Blogs { get; set; }
        public List<Say> Says { get; set; }
        public List<Carousel> Carousels { get; set; }
        public List<SliderImage> SliderImages { get; set; }
        public Slider Sliders { get; set; }
    }
}
