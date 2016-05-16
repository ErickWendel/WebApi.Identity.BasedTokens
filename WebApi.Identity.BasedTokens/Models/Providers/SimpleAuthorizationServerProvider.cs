using WebApi.Identity.BasedTokens.Models.Util;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace WebApi.Identity.BasedTokens.Models.Providers
{
    public sealed class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        private readonly AuthRepository _repository = new AuthRepository();

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context_)
        {
            context_.Validated();
            return Task.FromResult<object>(null);

        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context_)
        {
            context_.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
            var user = await _repository.FindUser(context_.UserName, context_.Password);
            if (user == null)
            {
                context_.SetError("invalid_grant", "O usuario ou senha estao incorretos");
                return;
            }

             var identity = await _repository.CreateIdentityAsync(user, context_.Options.AuthenticationType);
             identity.AddClaims(ExtendedClaimsProvider.GetClaims(user));

             var ticket = new AuthenticationTicket(identity, AuthUtil.GetProperties(user, identity.Claims));
            context_.Validated(ticket);

        }
      
        public override Task TokenEndpoint(OAuthTokenEndpointContext context_)
        {
            foreach (var property in context_.Properties.Dictionary)
                context_.AdditionalResponseParameters.Add(property.Key, property.Value);

            return Task.FromResult<object>(null);
        }

    }

}