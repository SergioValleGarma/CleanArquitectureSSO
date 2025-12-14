using SSO.Application.Features.Auth.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Common.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResponse> LoginAsync(string email, string password);
        Task<string> RegisterAsync(string email, string password, string nombre, string apellido);
        // Paso 1: Obtener la clave para mostrar el QR
        Task<TwoFactorSetupDto> GetTwoFactorSetupAsync(string userId);

        // Paso 2: Verificar código y activar 2FA
        Task<bool> EnableTwoFactorAsync(string userId, string code);
        // Paso 3: Desactivar 2FA 
        Task<bool> DisableTwoFactorAsync(string userId);
        // Login Paso 2: Verificar código al iniciar sesión
        Task<AuthResponse> LoginTwoFactorAsync(string email, string code);
    }
}
