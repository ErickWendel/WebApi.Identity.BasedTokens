using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace WebApi.Identity.BasedTokens.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public DateTime JoinDate { get; set; }

        [Required]
        public int PerfilSecundario { get; set; }
    }

    public enum PerfilSecundario
    {
        Provisionador
    }
}