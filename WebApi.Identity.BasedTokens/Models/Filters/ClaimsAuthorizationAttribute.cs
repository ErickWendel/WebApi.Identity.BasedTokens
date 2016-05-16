using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace WebApi.Identity.BasedTokens.Models.Filters
{
    public class ClaimsAuthorizeAttribute : AuthorizeAttribute
    {
        public string ClaimType { get; set; }
        public ClaimsAuthorizeAttribute() { }

        public override void OnAuthorization(HttpActionContext filterContext)
        {
            var user = filterContext.RequestContext.Principal as ClaimsPrincipal;

            if (!user.Identity.IsAuthenticated)
                base.HandleUnauthorizedRequest(filterContext);

            if (user.Claims.Any(x => x.Value == PerfilSecundario.Provisionador.ToString()) &&
                user.IsInRole(ClaimType))

                base.OnAuthorization(filterContext);

            else
                base.HandleUnauthorizedRequest(filterContext);
        }
    }
}