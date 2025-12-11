using SSO.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Domain.Entities
{
    public class Usuario : BaseEntity
    {
        public string Nombre { get; private set; }
        public string Apellido { get; private set; }
        public string Email { get; private set; }

        // No guardamos el Password aquí, Identity se encarga del Hash en Infraestructura.
        // Pero el dominio necesita saber que el usuario existe.

        public Usuario(string nombre, string apellido, string email)
        {
            Nombre = nombre;
            Apellido = apellido;
            Email = email;
        }
    }
}
