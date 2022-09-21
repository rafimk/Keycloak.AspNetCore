using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Keycloak.AspNetCore.Authorization
{
    public static class KeycloakAuthorizationServiceCollectionExtensions
    {
        public static IServiceCollection AddKeycloakAuthorization(this IServiceCollection services, Action<KeycloakAuthorizationOptions> configure)
        {
            services.AddAuthorization();
            services.Configure(configure);
            services.AddSingleton<IAuthorizationHandler, KeycloakAuthorizationHandler>();

            return services;
        }
    }
}