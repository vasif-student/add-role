using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class SliderImage
    {
        public int Id { get; set; }
        public string Image { get; set; }
        [NotMapped]
        public IFormFile File { get; set; }
        public Slider Slider { get; set; }
    }
}
