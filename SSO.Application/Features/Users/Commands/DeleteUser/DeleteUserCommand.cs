using MediatR;
using SSO.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Users.Commands.DeleteUser
{
    public record DeleteUserCommand(string UserId) : IRequest<bool>;

    public class DeleteUserCommandHandler : IRequestHandler<DeleteUserCommand, bool>
    {
        private readonly IUserService _userService;
        public DeleteUserCommandHandler(IUserService userService) => _userService = userService;

        public async Task<bool> Handle(DeleteUserCommand request, CancellationToken cancellationToken)
        {
            return await _userService.DeleteUserAsync(request.UserId);
        }
    }
}
