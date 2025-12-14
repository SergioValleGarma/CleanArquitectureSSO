using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Auth.Commands.Login;
using SSO.Application.Features.Auth.Commands.Register;
using SSO.Application.Features.Auth.Models;

namespace SSO.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IMediator _mediator;
        private readonly IAuthService _authService;

        public AuthController(IMediator mediator, IAuthService authService)
        {
            _mediator = mediator;
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginCommand command)
        {
            return Ok(await _mediator.Send(command));
        }

        // Aquí agregarías el endpoint de Register
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterCommand command)
        {
            // Retorna el ID del nuevo usuario
            return Ok(await _mediator.Send(command));
        }

        [Authorize] // Requiere estar logueado para configurar 2FA
        [HttpGet("2fa-setup")]
        public async Task<IActionResult> GetTwoFactorSetup()
        {
            // Obtener ID del usuario actual desde el Token
            var userId = User.FindFirst("uid")?.Value;
            var setup = await _authService.GetTwoFactorSetupAsync(userId); // Nota: Idealmente usa MediatR Commands, aquí acceso directo por brevedad
                                                                                        // OJO: Si usas IAuthService inyectado en el constructor del Controller, úsalo directo:
                                                                                        // var setup = await _authService.GetTwoFactorSetupAsync(userId);
            return Ok(setup);
        }

        [Authorize]
        [HttpPost("2fa-enable")]
        public async Task<IActionResult> EnableTwoFactor([FromBody] string code)
        {
            var userId = User.FindFirst("uid")?.Value;
            // OJO: Aquí deberías inyectar IAuthService en el controlador si no usas MediatR para todo
            // Asumo que inyectaste IAuthService _authService en el constructor
            var success = await _authService.EnableTwoFactorAsync(userId, code);
            if (success) return Ok("2FA Activado correctamente");
            return BadRequest("Código inválido");
        }

        [Authorize]
        [HttpPost("2fa-disable")]
        public async Task<IActionResult> DisableTwoFactor()
        {
            var userId = User.FindFirst("uid")?.Value;
            var success = await _authService.DisableTwoFactorAsync(userId);
            if (success) return Ok("2FA Desactivado correctamente");
            return BadRequest("No se pudo desactivar 2FA");
        }

        [AllowAnonymous] // Este es público porque es parte del login
        [HttpPost("login-2fa")]
        public async Task<IActionResult> Login2FA([FromBody] VerifyTwoFactorDto request)
        {
            try
            {
                var response = await _authService.LoginTwoFactorAsync(request.Email, request.Code);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Unauthorized(ex.Message);
            }
        }

    }
}
