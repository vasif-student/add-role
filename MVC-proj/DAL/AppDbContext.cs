using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MVC_proj.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVC_proj.DAL
{
    public class AppDbContext : IdentityDbContext<User>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {

        }

        public DbSet<Product> Products { get; set; }
        public DbSet<Category> Categories { get; set; }
        public DbSet<Layout> Layouts { get; set; }
        public DbSet<Blog> Blogs { get; set; }
        public DbSet<Say> Says { get; set; }
        public DbSet<Carousel> Carousels { get; set; }
        public DbSet<SliderImage> SliderImages { get; set; }
        public DbSet<Slider> Sliders { get; set; }

        //protected override void OnModelCreating(ModelBuilder modelBuilder)
        //{
        //    modelBuilder.Entity<Blog>(b =>
        //    {
        //        b.Property(p => p.Date).HasDefaultValueSql("DATEADD(HOUR,4,GETUTCDATE())");
        //    });
        //}
    }
}
