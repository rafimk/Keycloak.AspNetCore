using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Keycloak.AspNetCore.Authorization
{
    public class KeycloakAuthorizationPolicyProvider : IAuthorizationPolicyProvider
    {
        private readonly IOptions<KeycloakAuthorizationOptions> _options;
        private readonly IOptions<AuthorizationOptions> _authorizationOptions;
        private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;

        public KeycloakAuthorizationPolicyProvider(IOptions<KeycloakAuthorizationOptions> options, IOptions<AuthorizationOptions> authorizationOptions)
        {
            _options = options;
            _authorizationOptions = authorizationOptions;
            _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(authorizationOptions);
        }

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
            => _fallbackPolicyProvider.GetDefaultPolicyAsync();


        public Task<AuthorizationPolicy> GetFallbackPolicyAsync()
            => _fallbackPolicyProvider.GetFallbackPolicyAsync();

        public Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            if (_authorizationOptions.Value.GetPolicy(policyName) != null)
            {
                return _fallbackPolicyProvider.GetPolicyAsync(policyName);
            }

            var builder = new AuthorizationPolicyBuilder();
            builder.AuthenticationSchemes.Add(_options.Value.RequiredScheme);
            builder.AddRequirements(new KeycloakRequirement(policyName));
            return Task.FromResult(builder.Build());
        }
    }
}