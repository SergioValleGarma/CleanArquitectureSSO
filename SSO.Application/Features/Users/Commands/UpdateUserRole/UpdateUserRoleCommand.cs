using MediatR;
using SSO.Application.Common.Interfaces;


namespace SSO.Application.Features.Users.Commands.UpdateUserRole
{
    // CAMBIO: Comando para actualizar rol (reemplazar)
    public record UpdateUserRoleCommand(string UserId, string RoleName) : IRequest<bool>;

    public class UpdateUserRoleCommandHandler : IRequestHandler<UpdateUserRoleCommand, bool>
    {
        private readonly IUserService _userService;

        public UpdateUserRoleCommandHandler(IUserService userService)
        {
            _userService = userService;
        }

        public async Task<bool> Handle(UpdateUserRoleCommand request, CancellationToken cancellationToken)
        {
            return await _userService.UpdateUserRoleAsync(request.UserId, request.RoleName);
        }
    }
}
