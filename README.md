# ASPNetCore - IdentityServer4 + WEB-API JWT Token Issuer
[![Build Status](https://travis-ci.org/prbpedro/dotnetcoreidentityserverjwtissuer.svg?branch=master)](https://travis-ci.org/prbpedro/dotnetcoreidentityserverjwtissuer)

The IdentityServer4 is a Framework for OpenID and OAuth 2.0 connection to ASP.NET Core 2.2.

This framework provides various features such as service authentication, single sign-in (out), authentication/authorization with the use of digital certificates, and so on. It also makes use of a complex database structure that can be configured to use several different DBMS.

Through this tutorial we will create a WEB-API project with the aspnetcore 2.2 framework that should authenticate and authorize users through IdentityServer4 framework and, provide through a REST service, the user's security credentials as a JWT token.

To do so, we will use a PostgreSQL database, the framework ASPNetCore 2.2, the Framework IdentityServer4 and the Visual Studio Code Source Editor.

Running this application requires that the date/time of the machine has the time value of Coordinate Universal Time (UTC).

## Creating a database for the project

1. Create a new empty Database named TutorialBdIdentityServer that should contain the structures needed to run IdentityServer4.

1. Run the following SQL code to create the structures

    ```sql
    CREATE TABLE "AspNetRoles" (
        "Id" text NOT NULL,
        "Name" character varying(256) NULL,
        "NormalizedName" character varying(256) NULL,
        "ConcurrencyStamp" text NULL,
        CONSTRAINT "PK_AspNetRoles" PRIMARY KEY ("Id")
    );

    CREATE TABLE "AspNetUsers" (
        "Id" text NOT NULL,
        "UserName" character varying(256) NULL,
        "NormalizedUserName" character varying(256) NULL,
        "Email" character varying(256) NULL,
        "NormalizedEmail" character varying(256) NULL,
        "EmailConfirmed" boolean NOT NULL,
        "PasswordHash" text NULL,
        "SecurityStamp" text NULL,
        "ConcurrencyStamp" text NULL,
        "PhoneNumber" text NULL,
        "PhoneNumberConfirmed" boolean NOT NULL,
        "TwoFactorEnabled" boolean NOT NULL,
        "LockoutEnd" timestamp with time zone NULL,
        "LockoutEnabled" boolean NOT NULL,
        "AccessFailedCount" integer NOT NULL,
        CONSTRAINT "PK_AspNetUsers" PRIMARY KEY ("Id")
    );

    CREATE TABLE "AspNetRoleClaims" (
        "Id" serial NOT NULL,
        "RoleId" text NOT NULL,
        "ClaimType" text NULL,
        "ClaimValue" text NULL,
        CONSTRAINT "PK_AspNetRoleClaims" PRIMARY KEY ("Id"),
        CONSTRAINT "FK_AspNetRoleClaims_AspNetRoles_RoleId" FOREIGN KEY ("RoleId") REFERENCES "AspNetRoles" ("Id") ON DELETE CASCADE
    );

    CREATE TABLE "AspNetUserClaims" (
        "Id" serial NOT NULL,
        "UserId" text NOT NULL,
        "ClaimType" text NULL,
        "ClaimValue" text NULL,
        CONSTRAINT "PK_AspNetUserClaims" PRIMARY KEY ("Id"),
        CONSTRAINT "FK_AspNetUserClaims_AspNetUsers_UserId" FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
    );

    CREATE TABLE "AspNetUserLogins" (
        "LoginProvider" text NOT NULL,
        "ProviderKey" text NOT NULL,
        "ProviderDisplayName" text NULL,
        "UserId" text NOT NULL,
        CONSTRAINT "PK_AspNetUserLogins" PRIMARY KEY ("LoginProvider", "ProviderKey"),
        CONSTRAINT "FK_AspNetUserLogins_AspNetUsers_UserId" FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
    );

    CREATE TABLE "AspNetUserRoles" (
        "UserId" text NOT NULL,
        "RoleId" text NOT NULL,
        CONSTRAINT "PK_AspNetUserRoles" PRIMARY KEY ("UserId", "RoleId"),
        CONSTRAINT "FK_AspNetUserRoles_AspNetRoles_RoleId" FOREIGN KEY ("RoleId") REFERENCES "AspNetRoles" ("Id") ON DELETE CASCADE,
        CONSTRAINT "FK_AspNetUserRoles_AspNetUsers_UserId" FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
    );

    CREATE TABLE "AspNetUserTokens" (
        "UserId" text NOT NULL,
        "LoginProvider" text NOT NULL,
        "Name" text NOT NULL,
        "Value" text NULL,
        CONSTRAINT "PK_AspNetUserTokens" PRIMARY KEY ("UserId", "LoginProvider", "Name"),
        CONSTRAINT "FK_AspNetUserTokens_AspNetUsers_UserId" FOREIGN KEY ("UserId") REFERENCES "AspNetUsers" ("Id") ON DELETE CASCADE
    );

    CREATE INDEX "IX_AspNetRoleClaims_RoleId" ON "AspNetRoleClaims" ("RoleId");

    CREATE UNIQUE INDEX "RoleNameIndex" ON "AspNetRoles" ("NormalizedName");

    CREATE INDEX "IX_AspNetUserClaims_UserId" ON "AspNetUserClaims" ("UserId");

    CREATE INDEX "IX_AspNetUserLogins_UserId" ON "AspNetUserLogins" ("UserId");

    CREATE INDEX "IX_AspNetUserRoles_RoleId" ON "AspNetUserRoles" ("RoleId");

    CREATE INDEX "EmailIndex" ON "AspNetUsers" ("NormalizedEmail");

    CREATE UNIQUE INDEX "UserNameIndex" ON "AspNetUsers" ("NormalizedUserName");
    ```

## Creating an ASPNetCore 2.2 WEB-API project 

1. Open a folder that will contain the project
1. Create an ASPNetCore 2.2 WEB-API project using the command below in the Windows PowerShell terminal contained in VS Code.

	```csharp
    dotnet new webapi
	```
1. Add the required Microsoft.EntityFrameworkCore library to IdentityServer4 framework

	```csharp
    dotnet add package Microsoft.EntityFrameworkCore
	```
1. Add the required Npgsql.EntityFrameworkCore.PostgreSQL library to connect to PostGreSQL

	```csharp
    dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
	```
	
### Editing Program.cs class
Include the call to UseUrls method in the CreateWebHostBuilder method . Running this method determines the WEB-API's login URL and by default disables HTTPS in Kestrel. In a productive environment, the application should be accessed via HTTPS protocol.

```csharp
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseUrls("http://localhost:6000");
```

### Editing Startup.cs class

#### Including a constructor that enables configuration through an JSON file 

Include the constructor method as the code below

```csharp
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
```

Include the below files in the project root:

1. appsettings.json

    ```json
	{
		"Logging": {
			"LogLevel": {
				"Default": "Warning"
			}
		},
	    
		"AllowedHosts": "*",
	    
		"ASPNETCORE_IDENTITY_SERVER_BD": "Host=localhost;Username=postgres;Password=password;Database=TutorialBdIdentityServer;",
	}
    ```
2. appsettings.Development.json

	```json
	{
	}
    ```

Add the below ItemGroup  to the application csproj to ensure the copy of the files to the publishing directories.

```xml	
<ItemGroup>
	<none Include="appsettings.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
	<none Include="appsettings.Development.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
</ItemGroup>
```
	
#### Changing the dependency injector services configuration method

Create the AspnetCoreIdentityDbContext class that will be the interface to the IdentityServer4 framework with the database created through the Microsoft.EntityFrameworkCore ORM framework.

```csharp
namespace DotnetCoreIdentityServerJwt.Persistencia
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
```

This class defines that the user structure to use is that defined by the Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityUser class, other structures can be used as described in the IdentityServer4 framework documentation.

The method named ConfigureServices, found on Startup.cs class, should be changed as follows:

```csharp
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
}
```

The call to the AddDbContext method adds, to the dependency injector, the context with the database related to the ASPNETCORE_IDENTITY_SERVER_BD configuration variable.

The call to the AddIdentity method adds the user authentication and authorization service of the application's IdentityServer4 framework by configuring the use of the Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityUser and Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityRole structures for storing users and roles through the database created and referenced by the class AspnetCoreIdentityDbContext with the use of generation of standard tokens to change the password, email, telephone, etc. of the user.

The Configure method call defines that it will be necessary to enter a single e-mail address for each user's registration.

At the end of these changes, the IdentityServer4 framework will already be configured for use.

### Basic operation of the IdentityServer4 framework
The IdentityServer4 framework makes use of the following database structures for managing users:

1. AspNetUsers - Stores users
1. AspNetRoles - Store Roles
1. AspNetRoleClaims - Stores claims related to roles
1. AspNetUserRoles - Stores roles related users
1. AspNetUserClaims - Stores claims related to users
1. AspNetUserTokens - Stores the external authorization tokens
1. AspNetUserLogins - Stores the login data made using third-party libraries like Google, Facebook, etc.

The framework makes available through dependency injection the following classes for the manipulation and execution of tasks determined by the same:

1. Microsoft.AspNetCore.Identity.UserManager - Manages user-related operations
1. Microsoft.AspNetCore.Identity.RoleManager - Manages operations related to Roles
1. Microsoft.AspNetCore.Identity.SignInManager - Manages the operations related to the SingIn process

### Creating the service for managing data access maintained by the IdentityServer4 framework

Create the IdentityServiceException exception for the identification of errors generated by operations of the IdentityServer4 framework:

```csharp
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
```

Create the IdentityService.cs class according to the code below:

```csharp
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
```

This class will allow the application to insert basic data in the base referenced by the IdentityServer4 framework through the Inicializar method. The same will insert two roles, a user and relate this to one of the inserted roles.

The class also provides methods for obtaining roles associated with users and claims associated with roles and users through the ObterClaims and ObterRoles methods.

For user authentication use the AutenticarUsuario method.

### Creating an AspNetCore MVC controller to provide login method that returns a JWT token

Through the methods provided by the IdentityService class we will construct a REST method for the user's login that validate the password and audience and return a JWT token that contains the following duly completed claims:

1. JwtRegisteredClaimNames.Iss
1. JwtRegisteredClaimNames.Jti
1. JwtRegisteredClaimNames.Sub
1. JwtRegisteredClaimNames.UniqueName
1. JwtRegisteredClaimNames.Email
1. JwtRegisteredClaimNames.Exp
1. JwtRegisteredClaimNames.Nbf
1. JwtRegisteredClaimNames.AuthTime
1. JwtRegisteredClaimNames.Aud
1. Claims.Role
1. Claims related to roles and users managed by the IdentityServer4 framework

To do so, it will be necessary to create a DTO class with the necessary login data according to the code below:

```csharp
namespace DotnetCoreIdentityServerJwtIssuer.Dto
{
    public class LoginDto
    {
        public string Audience {get; set;}

        public string UserEmail {get; set;}

        public string UserPassword {get; set;}
    }
}
```

Create the LoginController class according to the code below:

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using DotnetCoreIdentityServerJwtIssuer.Dto;
using DotnetCoreIdentityServerJwtIssuer.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DotnetCoreIdentityServerJwtIssuer.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class LoginController : ControllerBase
	{
	    private IConfiguration Configuration;
	
	    private IdentityService IdentityService {get; set;}
	
	    public LoginController(IConfiguration config, IdentityService identityService)
	    {
	        Configuration = config;
	        IdentityService = identityService;
	    }
	
	    [HttpPost]
	    public IActionResult Post([FromBody]LoginDto dto)
	    {
	        IActionResult response = Unauthorized();
	        IdentityUser user = IdentityService.AutenticarUsuario(dto.UserEmail, dto.UserPassword);
	
	        if (Configuration.GetSection("AppSettings:jwt:audiences").Get<string[]>().Contains(dto.Audience) &&
	            user != null)
	        {
	            var tokenString = BuildToken(user, dto.Audience);
	            response = Ok(new { authorized = true, token = tokenString });
	        }
	
	        return response;
	    }
	
	    private string BuildToken(IdentityUser user, string audience)
	    {
	        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AppSettings:jwt:key"]));
	        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
	
	        IList<string> userRoles = IdentityService.ObterRoles(user);
	        IList<Claim> userClaims = IdentityService.ObterClaims(user);
	
	        DateTime now = DateTime.UtcNow;
	        DateTime expDateTime = now.AddMilliseconds(double.Parse(Configuration["AppSettings:jwt:millesecondsExp"])).ToUniversalTime();
	        long exp = EpochTime.GetIntDate(expDateTime);
	        IdentityOptions _options = new IdentityOptions();
	        List<Claim> claims = new List<Claim>
	        {
	            new Claim(JwtRegisteredClaimNames.Iss, Configuration["AppSettings:jwt:issuer"]),
	            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
	            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
	            new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
	            new Claim(JwtRegisteredClaimNames.Email, user.Email),
	            new Claim(JwtRegisteredClaimNames.Exp, exp.ToString()),
	            new Claim(JwtRegisteredClaimNames.Nbf,  ((DateTimeOffset)now).ToUnixTimeSeconds().ToString()),
	            new Claim(JwtRegisteredClaimNames.AuthTime, ((DateTimeOffset)now).ToUnixTimeSeconds().ToString()),
	            new Claim(JwtRegisteredClaimNames.Aud, audience)
	        };
	
	        claims.AddRange(userClaims);
	
	        foreach (string userRole in userRoles)
	        {
	            claims.Add(new Claim(ClaimTypes.Role, userRole));
	            IList<Claim> roleClaims = IdentityService.ObterClaims(userRole);
	            foreach(Claim roleClaim in roleClaims)
	            {
	                claims.Add(roleClaim);
	            }
	        }
	
	        ClaimsIdentity identity = new ClaimsIdentity(
	            new GenericIdentity(user.Id, "Jwt"),
	            claims
	        );
	
	        JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
	        SecurityToken securityToken = handler.CreateToken(new SecurityTokenDescriptor
	        {
	            Issuer = Configuration["AppSettings:jwt:issuer"],
	            SigningCredentials = credentials,
	            Subject = identity,
	            NotBefore = now,
	            IssuedAt = now,
	            Expires = expDateTime
	        });
	
	        return handler.WriteToken(securityToken);
	    }
	}
}
```

We can now add this service to the ServiceProvider by adding the code snippet below to the ConfigureServices method of the Startup class

```csharp
services.AddTransient(typeof(IdentityService));
``` 

We can also guarantee the call to the basic data initialization method with the following code snippet inserted in the Configure method of the Startup class

```csharp
IServiceScopeFactory serviceScopeFactory = (IServiceScopeFactory) app.ApplicationServices.GetService(typeof(IServiceScopeFactory));

using (IServiceScope scope = serviceScopeFactory.CreateScope())
{
    IServiceProvider services = scope.ServiceProvider;
    services.GetRequiredService<IdentityService>().Inicializar();
}
``` 

#### Adding needed configuration to the creation of the JWT token to the appsettings.json file

It's necessary to remember that the date time of the machine that will execute this application must be UTC.

The symmetric key, issuer, valid audiences and the expiration time in milliseconds needed to generate the token must be configurated on the  appsettings.json file as follow:

```json
"AppSettings": 
{
	"jwt": 
	{
		"key": "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
		"issuer": "http://localhost:6000/",
		"audiences": ["audience1","audience2"],
		"millesecondsExp": "36600000"
	}
}
```

Now the Login method is available throw the site <http://localhost:6000/api/Login> passing in the requisition body the following JSON text (application/JSON):

```json
{
	"Audience": "audience1",
	"UserEmail": "admin@serpro.gov.br",
	"UserPassword": "Sw0rdfi$h"
} 
```

Calling the Login method should return a JSON text similar to the below: 

```json
{
    "Authorized": true,
    "Created": "2019-04-17 17:44:10.4575850Z",
    "Expires": "2019-04-18 03:54:10.4575850Z",
    "AccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6WyIwMjlhZDAyNi1mZDZlLTQyMDctOTA5YS1mNzhjNjBmN2JlZjciLCJhZG1pbkBzZXJwcm8uZ292LmJyIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjAwMC8iLCJqdGkiOiIyNGZiMjEzNzg4MDY0MGZlYTA4NTQ2ZTBlNDhkZTQxMyIsInN1YiI6IjAyOWFkMDI2LWZkNmUtNDIwNy05MDlhLWY3OGM2MGY3YmVmNyIsImVtYWlsIjoiYWRtaW5Ac2VycHJvLmdvdi5iciIsImV4cCI6MTU1NTU1OTY1MCwibmJmIjoxNTU1NTIzMDUwLCJhdXRoX3RpbWUiOiIxNTU1NTIzMDUwIiwiYXVkIjoiYXVkaWVuY2UxIiwicm9sZSI6ImFkbWluaXN0cmFkb3IiLCJpYXQiOjE1NTU1MjMwNTB9.UR0XLqutQWhwPkSzcilwt-Yr2XD6Cvf11kpg8ZB3xxk"
}
```
