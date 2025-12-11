using MediatR;
using SSO.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Auth.Commands.Register
{
    // Datos que vienen del Frontend
    public record RegisterCommand(string Email, string Password, string Nombre, string Apellido) : IRequest<string>;

    public class RegisterCommandHandler : IRequestHandler<RegisterCommand, string>
    {
        private readonly IAuthService _authService;

        public RegisterCommandHandler(IAuthService authService)
        {
            _authService = authService;
        }

        public async Task<string> Handle(RegisterCommand request, CancellationToken cancellationToken)
        {
            // Delegamos al servicio de infraestructura
            return await _authService.RegisterAsync(request.Email, request.Password, request.Nombre, request.Apellido);
        }
    }
}
