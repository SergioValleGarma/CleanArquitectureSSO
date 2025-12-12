using MediatR;
using SSO.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Users.Queries.GetRoles
{
    public record GetRolesQuery : IRequest<List<string>>;
    public class GetRolesQueryHandler : IRequestHandler<GetRolesQuery, List<string>>
    {
        private readonly IUserService _userService;
        public GetRolesQueryHandler(IUserService userService)
        {
            _userService = userService;
        }
        public async Task<List<string>> Handle(GetRolesQuery request, CancellationToken cancellationToken)
        {
            return await _userService.GetAllRolesAsync();
        }
    }
}
