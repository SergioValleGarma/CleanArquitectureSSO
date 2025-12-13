using SSO.Application.Features.Roles.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Common.Interfaces
{
    public interface IRoleService
    {
        Task<List<RoleDto>> GetRolesAsync();
        Task<string> CreateRoleAsync(string roleName);
        Task DeleteRoleAsync(string roleId);

        // Gestión de Permisos
        Task<List<string>> GetPermissionsByRoleAsync(string roleId);
        Task UpdatePermissionsAsync(string roleId, List<string> permissions);
    }
}
