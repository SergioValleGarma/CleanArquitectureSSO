using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO.Application.Common.Security;
using SSO.Application.Features.Users.Commands.CreateUser;
using SSO.Application.Features.Users.Commands.DeleteUser;
using SSO.Application.Features.Users.Commands.UpdateUserRole;
using SSO.Application.Features.Users.Queries.GetRoles;
using SSO.Application.Features.Users.Queries.GetUsers;

namespace SSO.WebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    // Quitamos [Authorize(Roles = "Admin")] a nivel de clase para ser más granulares
    // Pero requerimos estar autenticado como mínimo
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly IMediator _mediator;

        public UsersController(IMediator mediator) => _mediator = mediator;

        // SOLO quien tenga Permiso de VER puede listar
        [HttpGet]
        [Authorize(Policy = Permissions.Users.View)]
        public async Task<IActionResult> GetAll() => Ok(await _mediator.Send(new GetUsersQuery()));

        [HttpGet("roles")]
        [Authorize(Policy = Permissions.Users.View)]
        public async Task<IActionResult> GetRoles() => Ok(await _mediator.Send(new GetRolesQuery()));

        // SOLO quien tenga Permiso de EDITAR puede cambiar roles
        [HttpPost("update-role")]
        [Authorize(Policy = Permissions.Users.Edit)]
        public async Task<IActionResult> UpdateRole(UpdateUserRoleCommand command)
        {
            return await _mediator.Send(command) ? Ok("Rol actualizado") : BadRequest("Error al actualizar");
        }

        // SOLO quien tenga Permiso de CREAR puede registrar
        [HttpPost("create")]
        [Authorize(Policy = Permissions.Users.Create)]
        public async Task<IActionResult> CreateUser(CreateUserCommand command)
        {
            try
            {
                var userId = await _mediator.Send(command);
                return Ok(new { userId });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // SOLO quien tenga Permiso de ELIMINAR puede borrar
        [HttpDelete("{id}")]
        [Authorize(Policy = Permissions.Users.Delete)]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var result = await _mediator.Send(new DeleteUserCommand(id));
            return result ? NoContent() : NotFound();
        }
    }
}
