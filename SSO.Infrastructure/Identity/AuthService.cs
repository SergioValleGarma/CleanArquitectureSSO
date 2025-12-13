using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SSO.Infrastructure.Identity
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager; // <--- 1. NUEVO: Inyectar RoleManager
        private readonly JwtSettings _jwtSettings;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<IdentityRole> roleManager, // <--- 1. NUEVO
            IOptions<JwtSettings> jwtSettings)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager; // <--- 1. NUEVO
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<AuthResponse> LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new Exception("Usuario no encontrado.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
                throw new Exception("Credenciales inválidas.");

            // CAMBIO: Ahora GenerateToken es asíncrono porque consulta a la BD
            var token = await GenerateToken(user);

            return new AuthResponse
            {
                Id = user.Id,
                Token = token,
                Email = user.Email,
                UserName = user.UserName
            };
        }

        public async Task<string> RegisterAsync(string email, string password, string nombre, string apellido)
        {
            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                Nombre = nombre,
                Apellido = apellido
            };

            var result = await _userManager.CreateAsync(user, password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new Exception($"Error al registrar: {errors}");
            }

            // Asignar rol por defecto
            await _userManager.AddToRoleAsync(user, "User");

            return user.Id;
        }

        // CAMBIO: Convertido a Task<string> async
        private async Task<string> GenerateToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", user.Id)
            };

            foreach (var roleName in userRoles)
            {
                // 1. Agregar el Rol al token
                claims.Add(new Claim(ClaimTypes.Role, roleName));

                // 2. NUEVO: Buscar el Rol en la BD para sacar sus Claims (Permisos)
                var role = await _roleManager.FindByNameAsync(roleName);
                if (role != null)
                {
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    foreach (var claim in roleClaims)
                    {
                        // Aquí se agregan "Permissions.Users.View", etc. al token
                        claims.Add(claim);
                    }
                }
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}