using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SSO.Domain.Entities;
using SSO.Infrastructure.Persistence.Contexts;
using SSO.Infrastructure.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Infrastructure.Persistence
{
    public static class IdentityDataSeeder
    {
        public static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager)
        {
            if (!await roleManager.RoleExistsAsync("Admin"))
            {
                await roleManager.CreateAsync(new IdentityRole("Admin"));
            }

            if (!await roleManager.RoleExistsAsync("Coordinador"))
            {
                await roleManager.CreateAsync(new IdentityRole("Coordinador"));
            }

            if (!await roleManager.RoleExistsAsync("User"))
            {
                await roleManager.CreateAsync(new IdentityRole("User"));
            }
        }

        public static async Task SeedPermissionsAsync(ApplicationDbContext context)
        {
            if (!context.SystemPermissions.Any())
            {
                var permissions = new List<SystemPermission>
                {
                    new SystemPermission("Permissions.Users.View", "Users", "Ver usuarios"),
                    new SystemPermission("Permissions.Users.Create", "Users", "Crear usuarios"),
                    new SystemPermission("Permissions.Users.Edit", "Users", "Editar usuarios"),
                    new SystemPermission("Permissions.Users.Delete", "Users", "Borrar usuarios"),
                    // ... agrega los de productos ...
                };

                await context.SystemPermissions.AddRangeAsync(permissions);
                await context.SaveChangesAsync();
            }
        }

        public static async Task SeedDefaultAdminAsync(UserManager<ApplicationUser> userManager)
        {
            var defaultUser = new ApplicationUser
            {
                UserName = "admin@sistema.com",
                Email = "admin@sistema.com",
                Nombre = "Administrador",
                Apellido = "Sistema",
                EmailConfirmed = true,
                PhoneNumberConfirmed = true
            };

            if (userManager.Users.All(u => u.Id != defaultUser.Id))
            {
                var user = await userManager.FindByEmailAsync(defaultUser.Email);
                if (user == null)
                {
                    // 1. Crear el usuario con una contraseña segura por defecto
                    var result = await userManager.CreateAsync(defaultUser, "Admin123!");

                    if (result.Succeeded)
                    {
                        // 2. Asignarle el rol de Admin
                        await userManager.AddToRoleAsync(defaultUser, "Admin");
                    }
                }
            }
        }

        public static async Task AssignAllPermissionsToAdminAsync(RoleManager<IdentityRole> roleManager, ApplicationDbContext context)
        {
            // 1. Buscar rol Admin
            var adminRole = await roleManager.FindByNameAsync("Admin");
            if (adminRole == null) return;

            // 2. Obtener todos los permisos del sistema
            var allPermissions = await context.SystemPermissions.ToListAsync();

            // 3. Obtener claims actuales del Admin
            var currentClaims = await roleManager.GetClaimsAsync(adminRole);

            // 4. Asignar los que falten
            foreach (var perm in allPermissions)
            {
                if (!currentClaims.Any(c => c.Type == "Permission" && c.Value == perm.Name))
                {
                    await roleManager.AddClaimAsync(adminRole, new System.Security.Claims.Claim("Permission", perm.Name));
                }
            }
        }
    }
}
