namespace DotnetCoreIdentityServerJwtIssuer.Persistencia
{
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;

    public class AspnetCoreIdentityDbContext : IdentityDbContext<IdentityUser>
    {
        public AspnetCoreIdentityDbContext(DbContextOptions<AspnetCoreIdentityDbContext> options)
            : base(options)
        {
        }
    }
}