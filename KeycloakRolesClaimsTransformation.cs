using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Keycloak.AspNetCore
{
    public class KeycloakRolesClaimsTransformation : IClaimsTransformation
    {
        private readonly string _roleClaimType;
        private readonly string _audience;

        public KeycloakRolesClaimsTransformation(string roleClaimType, string audience)
        {
            _roleClaimType = roleClaimType;
            _audience = audience;
        }

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var identity = principal.Identity as ClaimsIdentity;
            if (identity == null)
            {
                return Task.FromResult(principal);
            }

            var roles = identity.FindAll("resource_access").SelectMany(x => x.Value.Split(',')).ToList();
            var roleClaims = roles.Select(role => new Claim(ClaimTypes.Role, role));
            identity.AddClaims(roleClaims);

            return Task.FromResult(principal);
        }
    }
}