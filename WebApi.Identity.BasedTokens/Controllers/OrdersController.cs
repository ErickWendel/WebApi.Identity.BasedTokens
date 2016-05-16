using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using WebApi.Identity.BasedTokens.Models;
using WebApi.Identity.BasedTokens.Models.Filters;

namespace WebApi.Identity.BasedTokens.Controllers
{
    [RoutePrefix("api/Orders")]
    public sealed class OrdersController : ApiController
    {
        //[Authorize(Roles = Agencia,Modelo")]
        //[ClaimsAuthorize(ClaimType = "Modelo")]
        [Authorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            
            return Ok(Order.CreateOrders());
        }

 
    }
}
