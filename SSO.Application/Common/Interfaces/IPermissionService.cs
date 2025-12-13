using SSO.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Common.Interfaces
{
    public interface IPermissionService
    {
        Task<List<SystemPermission>> GetAllAsync();
        Task<SystemPermission> CreateAsync(string name, string module, string description);
        Task DeleteAsync(int id);
    }
}
