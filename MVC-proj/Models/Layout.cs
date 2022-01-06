using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class Layout
    {
        public int Id { get; set; }
        [Required]
        [MaxLength(70)]
        public string LinkedinUrl { get; set; }
        [Column("linkedin")]
        public string LinkedinTitle { get; set; }
        public string FacebookUrl { get; set; }
        public string FacebookTitle { get; set; }
        [MaxLength(50)]
        public string Description { get; set; }
        public string Image { get; set; }
        [NotMapped]
        public IFormFile File { get; set; }
    }
}
