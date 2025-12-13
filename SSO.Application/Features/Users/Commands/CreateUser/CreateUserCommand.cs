using MediatR;
using SSO.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Users.Commands.CreateUser
{
    public record CreateUserCommand(string Email, string Password, string Nombre, string Apellido, string Role) : IRequest<string>;

    public class CreateUserCommandHandler : IRequestHandler<CreateUserCommand, string>
    {
        private readonly IUserService _userService;
        public CreateUserCommandHandler(IUserService userService) => _userService = userService;

        public async Task<string> Handle(CreateUserCommand request, CancellationToken cancellationToken)
        {
            return await _userService.CreateUserAsync(request.Email, request.Password, request.Nombre, request.Apellido, request.Role);
        }
    }
}
