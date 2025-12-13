using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO.Application.Common.Interfaces;
using SSO.Application.Common.Security;
using SSO.Infrastructure.Identity;

namespace SSO.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles = "Admin")]
    public class RolesController : ControllerBase
    {
        private readonly IRoleService _roleService;
        private readonly IPermissionService _permissionService;

        public RolesController(IRoleService roleService, IPermissionService permissionService)
        {
            _roleService = roleService;
            _permissionService = permissionService;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll() 
            => Ok(await _roleService.GetRolesAsync());

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] string roleName)
            => Ok(await _roleService.CreateRoleAsync(roleName));

        [HttpDelete("{roleId}")]
        public async Task<IActionResult> Delete(string id)
        {
            await _roleService.DeleteRoleAsync(id);
            return NoContent();
        }

        [HttpGet("{id}/permissions")]
        public async Task<IActionResult> GetPermissions(string id)
            => Ok(await _roleService.GetPermissionsByRoleAsync(id));

        [HttpPut("{id}/permissions")]
        public async Task<IActionResult> UpdatePermissions(string id, [FromBody] List<string> permissions)
        {
            await _roleService.UpdatePermissionsAsync(id, permissions);
            return Ok();
        }

        // Endpoint auxiliar para que el Frontend sepa qué permisos existen en el sistema
        [HttpGet("system-permissions")]
        public async Task<IActionResult> GetAllSystemPermissions()
            => Ok(await _permissionService.GetAllAsync());
    }
}
