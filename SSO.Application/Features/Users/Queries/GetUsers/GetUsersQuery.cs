using MediatR;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Users.Models;


namespace SSO.Application.Features.Users.Queries.GetUsers
{
    public record GetUsersQuery : IRequest<List<UserDto>>;

    public class GetUsersQueryHandler : IRequestHandler<GetUsersQuery, List<UserDto>>
    {
        private readonly IUserService _userService;

        public GetUsersQueryHandler(IUserService userService)
        {
            _userService = userService;
        }

        public async Task<List<UserDto>> Handle(GetUsersQuery request, CancellationToken cancellationToken)
        {
            return await _userService.GetAllUsersAsync();
        }
    }
}
