using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SSO.Infrastructure.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
//using SSO.Domain.Common;

namespace SSO.Infrastructure.Persistence.Contexts
{
    // CAMBIO IMPORTANTE: Heredar de IdentityDbContext<ApplicationUser>
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        // Tus otros DbSets (Productos, etc.)
        // public DbSet<Producto> Productos { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            //builder.Ignore<BaseEvent>();
            base.OnModelCreating(builder); // Necesario para Identity
            // Tus configuraciones...
        }
    }
}
