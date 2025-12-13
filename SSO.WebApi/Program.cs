using Microsoft.AspNetCore.Identity;
using Microsoft.OpenApi.Models;
using SSO.Application;
using SSO.Application.Common.Security;
using SSO.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Mi SSO API", Version = "v1" });

    // Definir el esquema de seguridad (Botón Authorize)
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowReactApp",
        builder => builder
            .WithOrigins("http://localhost:5173") // Puerto por defecto de Vite
            .AllowAnyMethod()
            .AllowAnyHeader());
});
builder.Services.AddAuthorization(options =>
{
    // Registramos una política por cada permiso del sistema.
    // El nombre de la política será IGUAL al valor del permiso (ej: "Permissions.Users.View")
    foreach (var permission in Permissions.GetAll())
    {
        options.AddPolicy(permission, policy => policy.RequireClaim("Permission", permission));
    }
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowReactApp");
app.UseAuthentication(); // <--- ¡IMPORTANTE!
app.UseAuthorization();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var context = services.GetRequiredService<SSO.Infrastructure.Persistence.Contexts.ApplicationDbContext>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    // PASO A: Crear roles básicos
    await SSO.Infrastructure.Persistence.IdentityDataSeeder.SeedRolesAsync(roleManager);

    // PASO B: Llenar la tabla SystemPermissions (Catálogo)
    await SSO.Infrastructure.Persistence.IdentityDataSeeder.SeedPermissionsAsync(context);

    // PASO C: ¡CRUCIAL! Darle esos permisos al Rol Admin
    await SSO.Infrastructure.Persistence.IdentityDataSeeder.AssignAllPermissionsToAdminAsync(roleManager, context);
}

app.Run();
