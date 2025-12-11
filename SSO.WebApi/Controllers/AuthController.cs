using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO.Application.Features.Auth.Commands.Login;
using SSO.Application.Features.Auth.Commands.Register;

namespace SSO.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IMediator _mediator;

        public AuthController(IMediator mediator)
        {
            _mediator = mediator;
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
    }
}
