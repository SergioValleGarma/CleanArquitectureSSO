using MediatR;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Users.Commands.UpdateProfile
{
    public record UpdateProfileCommand(string UserId, string Nombre, string Apellido) : IRequest<bool>;

    // El Handler llamaría a _userManager.UpdateAsync(...) implementado en Infrastructure
    // Nota: Asegúrate de validar que el UserId del token coincida con el del comando
}
