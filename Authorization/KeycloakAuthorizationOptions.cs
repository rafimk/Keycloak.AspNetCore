using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Keycloak.AspNetCore.Authorization
{
    public class KeycloakAuthorizationOptions
    {
        public string RequiredScheme { get; set; } = JwtBearerDefaults.AuthenticationScheme;
        public string TokenEndpoint { get; set; }
        public HttpMessageHandler BackchannelHandler { get; set; } = new HttpClientHandler();
        public string Audience { get; set; }
    }
}