using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO.Application.Features.Auth.Models
{
    public class TwoFactorSetupDto
    {
        public string Key { get; set; } // La clave secreta (texto)
        public string QrCodeUri { get; set; } // La URL para generar el QR
        public bool IsEnabled { get; set; } // Indica si 2FA ya está activado
    }

    public class VerifyTwoFactorDto
    {
        public string Email { get; set; }
        public string Code { get; set; }
    }
}
