using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using DotnetCoreIdentityServerJwtIssuer.Persistencia;
using DotnetCoreIdentityServerJwtIssuer.Excecoes;
using System.Transactions;

namespace DotnetCoreIdentityServerJwtIssuer.Services
{
    public class IdentityService
    {
        private readonly UserManager<IdentityUser> UserManager;

        private readonly RoleManager<IdentityRole> RoleManager;

        private readonly AspnetCoreIdentityDbContext DbContext;
        
        private readonly SignInManager<IdentityUser>  SignInManager;

        public IdentityService(IServiceProvider serviceProvider)
        {
            UserManager = (UserManager<IdentityUser>) serviceProvider.GetService(typeof(UserManager<IdentityUser>));
            RoleManager = (RoleManager<IdentityRole>) serviceProvider.GetService(typeof(RoleManager<IdentityRole>));
            DbContext =  (AspnetCoreIdentityDbContext) serviceProvider.GetService(typeof(AspnetCoreIdentityDbContext));
            SignInManager =  (SignInManager<IdentityUser>) serviceProvider.GetService(typeof(SignInManager<IdentityUser>));
        }

        public void Inicializar()
        {
            foreach(string roleName in ApplicationRoles.VALUES)
            if (!RoleManager.RoleExistsAsync(roleName).Result)
            {
                IdentityResult result = RoleManager.CreateAsync(new IdentityRole(roleName)).Result;
                if(!result.Succeeded)
                {
                    throw new IdentityServiceException(result);
                }
            }

            if(UserManager.FindByEmailAsync("admin@serpro.gov.br").Result == null)
            {
                CriarUsuario("admin@serpro.gov.br", "Sw0rdfi$h", new string[]{ApplicationRoles.ADMINISTRADOR});
            }
        }

        public IdentityUser AutenticarUsuario(string userEmail, string userPassword)
        {
            IdentityUser user = UserManager.FindByEmailAsync(userEmail).Result;
            if(user!=null && SignInManager.CheckPasswordSignInAsync(user, userPassword, false).Result.Succeeded)
            {
               return user;
            }

            return null;
        }

        public IList<string> ObterRoles(IdentityUser user)
        {
            return UserManager.GetRolesAsync(user).Result;
        }

        public IList<Claim> ObterClaims(IdentityUser user)
        {
            return UserManager.GetClaimsAsync(user).Result;
        }

        public IList<Claim> ObterClaims(string role)
        {
            return RoleManager.GetClaimsAsync(RoleManager.FindByNameAsync(role).Result).Result;
        }

        public void CriarUsuario(string userEmail, string password, string[] roles)
        {
            using (var scope = new TransactionScope(TransactionScopeAsyncFlowOption.Enabled))
            {
                IdentityUser user = new IdentityUser()
                {
                    UserName = userEmail,
                    Email = userEmail,
                    EmailConfirmed = false,
                };

                IdentityResult result = UserManager.CreateAsync(user, password).Result;
                if(!result.Succeeded)
                {
                    throw new IdentityServiceException(result);
                }

                if (result.Succeeded)
                {
                    foreach(string role in roles)
                    {
                        result = UserManager.AddToRoleAsync(user, role).Result;
                        if(!result.Succeeded)
                        {
                            throw new IdentityServiceException(result);
                        }
                    }
                }

                scope.Complete();
            }
        }
    }
}