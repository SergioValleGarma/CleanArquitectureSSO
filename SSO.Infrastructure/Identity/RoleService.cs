using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Roles.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Infrastructure.Identity
{
    public class RoleService : IRoleService
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleService(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        public async Task<List<RoleDto>> GetRolesAsync()
        {
            return await _roleManager.Roles
                .Select(r => new RoleDto { Id = r.Id, Name = r.Name })
                .ToListAsync();
        }

        public async Task<string> CreateRoleAsync(string roleName)
        {
            var role = new IdentityRole(roleName);
            var result = await _roleManager.CreateAsync(role);
            if (!result.Succeeded) throw new Exception("Error creando rol");
            return role.Id;
        }

        public async Task DeleteRoleAsync(string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role != null) await _roleManager.DeleteAsync(role);
        }

        public async Task<List<string>> GetPermissionsByRoleAsync(string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role == null) return new List<string>();

            var claims = await _roleManager.GetClaimsAsync(role);
            return claims.Where(c => c.Type == "Permission").Select(c => c.Value).ToList();
        }

        public async Task UpdatePermissionsAsync(string roleId, List<string> permissions)
        {
            var role = await _roleManager.FindByIdAsync(roleId);
            if (role == null) throw new Exception("Rol no encontrado");

            // 1. Obtener claims actuales
            var currentClaims = await _roleManager.GetClaimsAsync(role);

            // 2. Borrar todos los claims de tipo "Permission"
            foreach (var claim in currentClaims.Where(c => c.Type == "Permission"))
            {
                await _roleManager.RemoveClaimAsync(role, claim);
            }

            // 3. Agregar los nuevos
            foreach (var permission in permissions)
            {
                await _roleManager.AddClaimAsync(role, new Claim("Permission", permission));
            }
        }
    }
}
