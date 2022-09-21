"# Keycloak.AspNetCore" 

var jwtOptions = Configuration.GetSection("JwtBearer").Get<JwtBearerOptions>();
var accessManagerOptions = Configuration.GetSection("AccessManager").Get<AccessManagerOptions>();

services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(option =>
        {
            options.Authority = jwtOptions.Authority;
            options.Audience = jwtOptions.Audience;
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters.ValidateLifetime = true;
            options.TokenValidationParameters.NameClaimType = "preferred_username";
            options.TokenValidationParameters.RoleClaimType = "role";

            options.Events = new AccessManagerJwtBearerEvents(accessManagerOptions);
        });

services.AddTransient<IClaimsTransformation>(_ => new KeycloakRolesClaimsTransformation("role", jwtOptions.Audience));

services.AddAuthorization(options => 
{
    # region
    options.AddPolicy(Policies.CanViewStatus, policy => policy.RequiresKeycloakEntitlement("CanSee", "VIEW"));
    # endregion
});


Infra.Identity

public static class Policy
{
    # region
    public const string CanView = "CanView"
    # endregion
}