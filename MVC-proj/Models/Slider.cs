using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class Slider
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string Desc { get; set; }
        public string Sign { get; set; }
        public List<SliderImage> SliderImages { get; set; }
        [NotMapped]
        public IFormFile File { get; set; }
    }
}
