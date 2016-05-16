using Microsoft.Owin;
using Microsoft.Owin.Cors;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using WebApi.Identity.BasedTokens.Models.Providers;
using Microsoft.Owin.Security.Facebook;
using Microsoft.AspNet.Identity;

[assembly: OwinStartup(typeof(WebApi.Identity.BasedTokens.Startup))]
namespace WebApi.Identity.BasedTokens
{
    public class Startup
    {
        public static OAuthBearerAuthenticationOptions OAuthBearerOptions { get; private set; }
        public static FacebookAuthenticationOptions facebookAuthOptions { get; private set; }

        public void Configuration(IAppBuilder app_)
        {
            HttpConfiguration config = new HttpConfiguration();
            ConfigureAuth(app_);

            WebApiConfig.Register(config);

            app_.UseCors(CorsOptions.AllowAll);
            app_.UseWebApi(config);
        }

        public void ConfigureAuth(IAppBuilder app_)
        {
            var oAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/api/login"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(1),
                Provider = new SimpleAuthorizationServerProvider()
            };

            app_.UseOAuthAuthorizationServer(oAuthServerOptions);
            OAuthBearerOptions = new OAuthBearerAuthenticationOptions();
            app_.UseOAuthBearerAuthentication(OAuthBearerOptions);
            app_.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            facebookAuthOptions = new FacebookAuthenticationOptions()
            {
                AppId = "777234509007879",
                AppSecret = "86d6ac6d07cb789e6de94762ec397632",
                Provider = new FacebookAuthProvider()
            };
            app_.UseFacebookAuthentication(facebookAuthOptions);
        }


    }
}