using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace WebApi.Identity.BasedTokens.Models.Util
{
    public class AuthUtil
    {
        public static AuthenticationProperties GetProperties(ApplicationUser user_, IEnumerable<Claim> claims_)
        {
            IDictionary<string, string> data = new Dictionary<string, string>();
            data.Add(new KeyValuePair<string, string>("claims", string.Join(",", claims_)));
            return new AuthenticationProperties(data);
        }
    }
}