using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO.Application.Features.Users.Commands.UpdateUserRole;
using SSO.Application.Features.Users.Queries.GetRoles;
using SSO.Application.Features.Users.Queries.GetUsers;

namespace SSO.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class UsersController : ControllerBase
    {
        private readonly IMediator _mediator;
        public UsersController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            // Aquí podrías implementar la lógica para obtener todos los usuarios
            return Ok(await _mediator.Send(new GetUsersQuery()));
        }
        [HttpGet("roles")]
        public async Task<IActionResult> GetRoles()
        {
            // Aquí podrías implementar la lógica para obtener todos los roles
            return Ok(await _mediator.Send(new GetRolesQuery()));
        }
        [HttpPost("update-role")]
        public async Task<IActionResult> UpdateRole(UpdateUserRoleCommand command)
        {
            var result = await _mediator.Send(command);
            if (result) return Ok("Rol actualizado correctamente");
            return BadRequest("Error al actualizar rol");
        }
    }
}
