using Microsoft.AspNetCore.Authorization;

namespace Keycloak.AspNetCore.Authorization
{
    public class KeycloakRequirement : IAuthorizationRequirement
    {
        public string PolicyName { get; }

        public KeycloakRequirement(string policyName)
        {
            PolicyName = policyName;
        }
    }
}