using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Areas.Admin.ViewModels
{
    public class SliderImageCreateViewModel
    {
        public IFormFile[] Files {get;set;}
    }
}
