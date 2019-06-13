using System;
using DotnetCoreIdentityServerJwtIssuer.Persistencia;
using DotnetCoreIdentityServerJwtIssuer.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DotnetCoreIdentityServerJwt
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public IHostingEnvironment HostingEnvironment { get; }

        public Startup(IHostingEnvironment env)
        {
            HostingEnvironment = env;
            Configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: false)
                .AddEnvironmentVariables()
                .Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
            
            services.AddDbContext<AspnetCoreIdentityDbContext>(
                options => options.UseNpgsql(Configuration.GetSection("ASPNETCORE_IDENTITY_SERVER_BD").Value)
            );

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<AspnetCoreIdentityDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.User.RequireUniqueEmail = true;
            });

            services.AddTransient(typeof(IdentityService));
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseMvc();

            IServiceScopeFactory serviceScopeFactory = (IServiceScopeFactory) app.ApplicationServices.GetService(typeof(IServiceScopeFactory));

            using (IServiceScope scope = serviceScopeFactory.CreateScope())
            {
                IServiceProvider services = scope.ServiceProvider;
                services.GetRequiredService<IdentityService>().Inicializar();
            }
        }
    }
}
