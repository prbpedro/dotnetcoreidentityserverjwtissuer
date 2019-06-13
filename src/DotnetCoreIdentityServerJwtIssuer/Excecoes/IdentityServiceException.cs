using System;
using Microsoft.AspNetCore.Identity;

namespace DotnetCoreIdentityServerJwtIssuer.Excecoes
{
    public class IdentityServiceException : Exception
    {
        public IdentityServiceException(IdentityResult identityResult)
        : base("Erro em operação do IdentityServer")
        {
            foreach(IdentityError identityError in identityResult.Errors)
            {
                Data.Add(identityError.Code, identityError.Description);
            }
        }
    }
}