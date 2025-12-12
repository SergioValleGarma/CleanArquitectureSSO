using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Users.Models
{
    public class UserDto
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string Nombre { get; set; }
        public string Apellido { get; set; }
        public List<string> Roles { get; set; }
    }
}
