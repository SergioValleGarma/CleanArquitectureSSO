using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SSO.WebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult GetSecureData()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("uid")?.Value;
            var email = User.FindFirst(ClaimTypes.Email)?.Value;

            return Ok(new
            {
                Mensaje = "¡Acceso Autorizado! Estas viendo datos protegidos, no admin.",
                UsuarioId = userId,
                UsuarioEmail = email,
                HoraServidor = DateTime.UtcNow
            });
        }

        [HttpGet("admin-data")]
        [Authorize(Roles = "Admin")]//solo admins
        public IActionResult GetAdminData()
        {
            return Ok(new
            {
                Mensaje = "¡Acceso Autorizado! Estas viendo datos de administrador.",
                HoraServidor = DateTime.UtcNow
            });
        }

        [HttpGet("public-data")]
        [Authorize]//cualquier usuario autenticado
        public IActionResult GetPublicData()
        {
            return Ok(new
            {
                Mensaje = "¡Acceso Autorizado! Estas viendo datos públicos para usuarios autenticados.",
                HoraServidor = DateTime.UtcNow
            });
        }

    }
}
