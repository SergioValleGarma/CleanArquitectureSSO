using Microsoft.AspNetCore.Identity;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Users.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace SSO.Infrastructure.Identity
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<List<UserDto>> GetAllUsersAsync()
        {
            var users = await _userManager.Users.ToListAsync();
            var result = new List<UserDto>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                result.Add(new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    Nombre = user.Nombre,
                    Apellido = user.Apellido,
                    Roles = roles.ToList()
                });
            }

            return result;
        }

        public async Task<bool> UpdateUserRoleAsync(string userId, string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            // 1. Obtener roles actuales
            var currentRoles = await _userManager.GetRolesAsync(user);

            // 2. Remover TODOS los roles actuales (Para evitar acumular User + Admin)
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
            if (!removeResult.Succeeded) return false;

            // 3. Añadir el nuevo rol seleccionado
            var addResult = await _userManager.AddToRoleAsync(user, roleName);
            return addResult.Succeeded;
        }

        public async Task<List<string>> GetAllRolesAsync()
        {
            return await _roleManager.Roles
                .Select(r => r.Name)
                .ToListAsync();
        }

        public async Task<string> CreateUserAsync(string email, string password, string nombre, string apellido, string role)
        {
            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                Nombre = nombre,
                Apellido = apellido
            };

            var result = await _userManager.CreateAsync(user, password);
            if (!result.Succeeded) throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

            if (!string.IsNullOrEmpty(role) && await _roleManager.RoleExistsAsync(role))
            {
                await _userManager.AddToRoleAsync(user, role);
            }
            else
            {
                await _userManager.AddToRoleAsync(user, "User"); // Rol por defecto
            }

            return user.Id;
        }

        public async Task<bool> DeleteUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;
            var result = await _userManager.DeleteAsync(user);
            return result.Succeeded;
        }
    }
}
