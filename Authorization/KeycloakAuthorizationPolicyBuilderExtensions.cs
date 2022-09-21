using Microsoft.AspNetCore.Authorization;

namespace Keycloak.AspNetCore.Authorization
{
    public static class KeycloakAuthorizationPolicyBuilderExtensions
    {
        public static AuthorizationPolicyBuilder RequireKeycloakEntitlement(this AuthorizationPolicyBuilder builder, string resource, string scope)
        {
            builder.Requirements.Add(new KeycloakRequirement($"{resource}#{scope}"));
            return builder;
        }
    }
}