using SSO.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Domain.Entities
{
    public class SystemPermission : BaseEntity
    {
        public string Name { get; set; }  // Ej: Permissions.Users.Create
        public string Module { get; set; } // Ej: Users, Products (Para agrupar en UI)
        public string Description { get; set; } // Ej: Permite crear nuevos usuarios

        public SystemPermission(string name, string module, string description)
        {
            Name = name;
            Module = module;
            Description = description;
        }
    }
}
