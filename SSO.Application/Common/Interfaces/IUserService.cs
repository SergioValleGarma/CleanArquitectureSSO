using SSO.Application.Features.Users.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Common.Interfaces
{
    public interface IUserService
    {
        Task<List<UserDto>> GetAllUsersAsync();
        Task<bool> UpdateUserRoleAsync(string userId, string roleName);
        Task<List<string>> GetAllRolesAsync();
        Task<string> CreateUserAsync(string email, string password, string nombre, string apellido, string role);
        Task<bool> DeleteUserAsync(string userId);
    }
}
