using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace WebApi.Identity.BasedTokens.Models
{
    public sealed class AuthRepository : IDisposable
    {
        private AuthContext _ctx;
        private UserManager<ApplicationUser> _userManager;
        private RoleManager<IdentityRole> _roleManager;
        public AuthRepository()
        {
            _ctx = new AuthContext();
            _userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(_ctx));
            _roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(_ctx));

        }

        public async Task<IdentityResult> RegisterUserAsync(UserModel userModel_)
        {
            var user = new ApplicationUser
            {
                UserName = userModel_.UserName,
                JoinDate = DateTime.Now

            };
            var result = await _userManager.CreateAsync(user, userModel_.Password);
            var userExistent = await _userManager.FindAsync(userModel_.UserName, userModel_.Password);
            var perfil = ((Perfis)userModel_.PerfilId).ToString();
            await _userManager.AddToRolesAsync(userExistent.Id.ToString(), new string[] { perfil });

            return result;
        }

        public async Task<ApplicationUser> FindUser(string userName_, string password_)
        {
            var user = await _userManager.FindAsync(userName_, password_);
            return user;
        }

        public async Task<ClaimsIdentity> CreateIdentityAsync(ApplicationUser user_, string authenticationType_)
        {
            var user = await _userManager.CreateIdentityAsync(user_, authenticationType_);
            return user;
        }
        public async Task<IdentityUser> FindAsync(UserLoginInfo loginInfo)
        {
            IdentityUser user = await _userManager.FindAsync(loginInfo);

            return user;
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user_)
        { 
            var result = await _userManager.CreateAsync(user_);

            return result;
        }

        public async Task<IdentityResult> AddLoginAsync(string userId_, UserLoginInfo login_)
        {
            var result = await _userManager.AddLoginAsync(userId_, login_);

            return result;
        }
        public void CreateRoles()
        {
            _roleManager.Create(new IdentityRole { Name = "Admin" });
            _roleManager.Create(new IdentityRole { Name = "Modelo" });
            _roleManager.Create(new IdentityRole { Name = "Agencia" });


        }

        public void CreateClaimsAsync()
        {
            var user = _userManager.FindByName("UserAgencia243");
            //await _userManager.AddClaimAsync(user.Id, new Claim();
        }

        public void Dispose()
        {
            _ctx.Dispose();
            _userManager.Dispose();
        }
    }
}