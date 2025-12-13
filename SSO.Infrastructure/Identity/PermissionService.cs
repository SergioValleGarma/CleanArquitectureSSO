using Microsoft.EntityFrameworkCore;
using SSO.Application.Common.Interfaces;
using SSO.Domain.Entities;
using SSO.Infrastructure.Persistence.Contexts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Infrastructure.Identity
{
    public class PermissionService : IPermissionService
    {
        private readonly ApplicationDbContext _context;

        public PermissionService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<List<SystemPermission>> GetAllAsync()
        {
            return await _context.SystemPermissions.OrderBy(p => p.Module).ThenBy(p => p.Name).ToListAsync();
        }

        public async Task<SystemPermission> CreateAsync(string name, string module, string description)
        {
            if (await _context.SystemPermissions.AnyAsync(p => p.Name == name))
                throw new Exception($"El permiso {name} ya existe.");

            var perm = new SystemPermission(name, module, description);
            await _context.SystemPermissions.AddAsync(perm);
            await _context.SaveChangesAsync();
            return perm;
        }

        public async Task DeleteAsync(int id)
        {
            var perm = await _context.SystemPermissions.FindAsync(id);
            if (perm != null)
            {
                _context.SystemPermissions.Remove(perm);
                await _context.SaveChangesAsync();
            }
        }
    }
}
