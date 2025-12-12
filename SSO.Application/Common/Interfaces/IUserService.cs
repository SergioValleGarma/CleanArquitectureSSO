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
        //Task<List<string>> GetUserRolesAsync(string userId);
    }
}
