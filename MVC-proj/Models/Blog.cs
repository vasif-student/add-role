using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.Models
{
    public class Blog
    {

        private DateTime _date;
        public int Id { get; set; }
        public string Image { get; set; }
        public DateTime Date
        {
            get
            {
                return this._date;
            }
            set
            {
                this._date = DateTime.Now;
            }
        }
        public string Title { get; set; }
        public string Desc { get; set; }
    }
}
