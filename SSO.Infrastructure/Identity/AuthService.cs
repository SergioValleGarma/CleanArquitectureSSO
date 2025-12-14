using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SSO.Application.Common.Interfaces;
using SSO.Application.Features.Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace SSO.Infrastructure.Identity
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager; // <--- 1. NUEVO: Inyectar RoleManager
        private readonly JwtSettings _jwtSettings;
        private readonly UrlEncoder _urlEncoder;

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
            _urlEncoder = UrlEncoder.Default;
        }

        public async Task<AuthResponse> LoginAsync(string email, string password)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) throw new Exception("Usuario no encontrado.");

            // Usamos PasswordSignInAsync en lugar de CheckPassword para que detecte si requiere 2FA
            var result = await _signInManager.PasswordSignInAsync(user, password, false, false);

            if (result.RequiresTwoFactor)
            {
                // NO devolvemos token todavía. Devolvemos un indicador especial.
                return new AuthResponse
                {
                    Id = user.Id,
                    Email = user.Email,
                    Token = "2FA_REQUIRED" // Bandera para el frontend
                };
            }

            if (!result.Succeeded) throw new Exception("Credenciales inválidas.");

            // Login normal exitoso
            var token = await GenerateToken(user);
            return new AuthResponse { Id = user.Id, Token = token, Email = user.Email, UserName = user.UserName };
        }

        // --- NUEVOS MÉTODOS 2FA ---

        public async Task<TwoFactorSetupDto> GetTwoFactorSetupAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) throw new Exception("Usuario no encontrado");

            // Resetear clave si ya existía para asegurar una nueva
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);

            // Generar URI para el QR (Formato estándar otpauth)
            var email = user.Email;
            var appName = "MiSistemaSSO"; // El nombre que saldrá en la app del cel
            var qrUri = string.Format(
                "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
                _urlEncoder.Encode(appName),
                _urlEncoder.Encode(email),
                unformattedKey);

            return new TwoFactorSetupDto { Key = unformattedKey, QrCodeUri = qrUri };
        }

        public async Task<bool> EnableTwoFactorAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId);

            // Validar el código ingresado contra la clave que acabamos de generar
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

            if (isValid)
            {
                await _userManager.SetTwoFactorEnabledAsync(user, true);
                return true;
            }
            return false;
        }

        public async Task<AuthResponse> LoginTwoFactorAsync(string email, string code)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) throw new Exception("Usuario no encontrado");

            // Verificar el código TOTP
            // Nota: Para login real con SignInManager se usa TwoFactorSignInAsync, 
            // pero como usamos JWT stateless, verificamos el token manualmente.
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, code);

            if (!isValid) throw new Exception("Código de seguridad inválido.");

            // Código correcto -> Generar JWT
            var token = await GenerateToken(user);
            return new AuthResponse { Id = user.Id, Token = token, Email = user.Email, UserName = user.UserName };
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