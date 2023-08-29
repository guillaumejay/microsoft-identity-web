using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.InMemory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web.OWIN;
using System.Web.Services.Description;
using Microsoft.IdentityModel.Logging;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using System.Web;
using System.Text.Json.Serialization;
using System.Text.Json;
using System;
using System.Text;
using System.IdentityModel;
using static System.Net.WebRequestMethods;

namespace OwinWebApp
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            IdentityModelEventSource.ShowPII = Debugger.IsAttached;
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            
            OwinTokenAcquirerFactory factory = TokenAcquirerFactory.GetDefaultInstance<OwinTokenAcquirerFactory>();

            app.AddMicrosoftIdentityWebApp(factory,null,UpdateOptions);
            factory.Services
                .Configure<ConfidentialClientApplicationOptions>(options =>
                {
                    options.RedirectUri = "https://localhost:44386/";
                    
                })
                //.AddMicrosoftGraph()
                //.AddDownstreamApi("DownstreamAPI1", factory.Configuration.GetSection("DownstreamAPI"))
                .AddInMemoryTokenCaches();
            factory.Build();

            /*
            app.AddMicrosoftIdentityWebApp(configureServices: services =>
            {
                services
                .Configure<ConfidentialClientApplicationOptions>(options => { options.RedirectUri = "https://localhost:44386/"; })
                .AddMicrosoftGraph()
               // WE cannot do that today: Configuration is not available.
               // .AddDownstreamApi("CalledApi", null)
                .AddInMemoryTokenCaches();
            });
            */

        }

        private void UpdateOptions(OpenIdConnectAuthenticationOptions obj)
        {
            obj.Scope = "openid";
            obj.RedirectUri = "https://localhost:44386/";
            obj.Notifications.SecurityTokenValidated =  context =>
            {
                HttpContextBase httpContext = context.OwinContext.Get<HttpContextBase>(typeof(HttpContextBase).FullName);

                if (httpContext.Session[ClaimConstants.ClientInfo] is string clientInfo && !string.IsNullOrEmpty(clientInfo))
                {
                    ClientInfo? clientInfoFromServer = ClientInfo.CreateFromJson(clientInfo);

                    if (clientInfoFromServer != null && clientInfoFromServer.UniqueTenantIdentifier != null && clientInfoFromServer.UniqueObjectIdentifier != null)
                    {
                        context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimConstants.UniqueTenantIdentifier, clientInfoFromServer.UniqueTenantIdentifier));
                        context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimConstants.UniqueObjectIdentifier, clientInfoFromServer.UniqueObjectIdentifier));
                    }
                    httpContext.Session.Remove(ClaimConstants.ClientInfo);
                }
                // string name = context.AuthenticationTicket.Identity.FindFirst("preferred_username").Value;
                string name = context.AuthenticationTicket.Identity.FindFirst("name").Value;
                context.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Name, name, string.Empty));
                return Task.CompletedTask;
            };  
        }
    }
    internal class ClientInfo
    {
        [JsonPropertyName(ClaimConstants.UniqueObjectIdentifier)]
        public string? UniqueObjectIdentifier { get; set; } = null;

        [JsonPropertyName(ClaimConstants.UniqueTenantIdentifier)]
        public string? UniqueTenantIdentifier { get; set; } = null;

#if NET6_0_OR_GREATER
        [RequiresUnreferencedCode("Calls Microsoft.Identity.Web.ClientInfo.DeserializeFromJson(byte[]).")]
#endif
        public static ClientInfo? CreateFromJson(string? clientInfo)
        {
            if (string.IsNullOrEmpty(clientInfo))
            {
                throw new ArgumentNullException(nameof(clientInfo), "IDW10402: Client info returned from the server is null.");
            }

         var base64EncodedBytes = System.Convert.FromBase64String(clientInfo);

 return DeserializeFromJson(base64EncodedBytes);
 
 }
        internal static ClientInfo? DeserializeFromJson(byte[]? jsonByteArray)
        {
            if (jsonByteArray == null || jsonByteArray.Length == 0)
            {
                return default;
            }

            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            };

            return JsonSerializer.Deserialize<ClientInfo>(jsonByteArray, options);
        }
    }
}
