using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class BasicEntity
    {
        public int Id { get; set; }
        [Required(ErrorMessage ="Bosh ola bilmez")]
        public string Name { get; set; }
    }
}
