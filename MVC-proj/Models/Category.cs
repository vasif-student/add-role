using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class Category : BasicEntity
    {
        [MaxLength(200)]
        public string Description { get; set; }
        public ICollection<Product> Products { get; set; }
    }
}
