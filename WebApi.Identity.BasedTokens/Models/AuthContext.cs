using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration;
using System.Linq;
using System.Web;
using Microsoft.AspNet.Identity;


namespace WebApi.Identity.BasedTokens.Models
{
    public sealed class AuthContext : IdentityDbContext<ApplicationUser>
    {
        public AuthContext(): base("AuthContext")
        {

        }
    }
}