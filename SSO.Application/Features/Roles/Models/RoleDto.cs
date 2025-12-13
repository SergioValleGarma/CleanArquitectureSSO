using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Roles.Models
{
    public class RoleDto
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }

    public class PermissionDto
    {
        public string RoleId { get; set; }
        public List<string> Permissions { get; set; } // Lista de Claims seleccionados
    }
}
