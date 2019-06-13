# ASPNetCore - IdentityServer4 + JWT Token Issuer

O <b>IdentityServer4</b> é um <i>framework</i>  para conexão <b>OpenID</b> e <b>OAuth 2.0</b> para o <b>ASP.NET Core 2</b>. 

Este <i>framework</i> traz vários recursos como a autenticação como serviço, <i>single sing-in(out)</i>, autenticação/autorização com a utilização de certificados digitais, etc. O mesmo faz uso de uma estrutura de banco de dados complexa que pode ser configurada para a utilização de vários <b>SGBDS</b> distintos.

Através deste tutorial iremos criar um projeto <b>web-api</b> com o <i>framework</i> <b>aspnetcore 2.2</b> que deverá fazer a autenticação/autorização dos usuários através do <i>framework</i> <b>IdentityServer4</b> e fornecer, através de um serviço <b>REST</b>, as credenciais de segurança dos usuários como um token JWT.

Para tanto faremos uso de um banco de dados <b>PostgreSQL</b>, o <i>framework</i> <b>ASPNetCore 2.2</b>, o <i>framework</i> <b>IdentityServer4</b> e o editor de código fonte <b>Visual Studio Code</b>.

A execução desta aplicação necessita que a data/hora da máquina tenha como fuso horário o valor UTC - Tempo Universal Coordenado.

## Criar base de dados para projeto
1. Crie um novo <i>Database</i> que deverá conter as definições das estruturas necessárias ao funcionamento do IdentityServer4

Neste primeiro momento a base de dados deverá ficar vazia. A criação das tabelas será feita via scripts em um momento posterior.

## Criar um projeto web-api ASPNetCore 2.2

1. Abra uma pasta que deverá conter o projeto a ser criado
1. Crie um projeto web-api ASPNetCore 2.2 através do comando abaixo no terminal <b>Windows PowerShell</b> contido no <b>VS Code</b>.

	```csharp
    dotnet new webapi
	```
1. Adicione a biblioteca <b>Microsoft.EntityFrameworkCore</b> necessária ao <b>IdentityServer4</b>

	```csharp
    dotnet add package Microsoft.EntityFrameworkCore
	```
1. Adicione a biblioteca <b>Npgsql.EntityFrameworkCore.PostgreSQL</b> necessária para conectar com bancos de dados <b>PostGreSQL</b>

	```csharp
    dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
	```
	
### Editar classe Program.cs
Incluir chamada ao método <i>UseUrls</i> no método <i>CreateWebHostBuilderconforme</i>. A execução deste método determina a URL de entrada do web-api e por padrão desabilita o HTTPS no Kestrel. Em um ambiente produtivo a aplicação deverá ser acessada via protocolo HTTPS.

```csharp
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .UseStartup<Startup>()
                .UseUrls("http://localhost:6000");
```

### Editar classe Startup.cs

#### Incluir construtor que habilita configuração via arquivo json

Incluir construtor conforme código abaixo habilitando assim a configuração do componente via arquivo json.

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

Incluir na raiz do projeto os arquivos:

1. appsettings.json

    ```json
	{
		"Logging": {
			"LogLevel": {
				"Default": "Warning"
			}
		},
	    
		"AllowedHosts": "*",
	    
		"ASPNETCORE_IDENTITY_SERVER_BD" : "string de conexão com o banco criado"
	}
    ```
2. appsettings.Development.json

	```json
	{
	}
    ```

Adicionar ao <i>csproj</i> da aplicação o ItemGroup abaixo para forçar a cópia dos arquivos para os diretórios de publicação.

```xml	
<ItemGroup>
	<none Include="appsettings.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
    <none Include="appsettings.Development.json" CopyToOutputDirectory="Always" CopyToPublishDirectory="Always"/>
</ItemGroup>
```
	
#### Alterar método de configuração dos serviços de injetor de dependências

Deverá ser criada a classe <b>AspnetCoreIdentityDbContext</b> que servirá de interface para o <i>framework</i> <b>IdentityServer4</b> com o banco de dados criado através do <i>framework</i> ORM <b>Microsoft.EntityFrameworkCore</b>.

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

Esta classe define que a estrutura de usuário a ser utilizada é a definida pela classe <b>Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityUser</b>, outras estruturas podem ser utilizadas conforme descrito na documentação do <i>framework</i> <b>IdentityServer4</b>.

O método nomeado <i>ConfigureServices</i>, pertencente a classe <b>Startup.cs</b>, deverá ser alterado conforme código abaixo:

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

A chamada ao método <i>AddDbContext</i> adiciona ao injetor de dependências o contexto com a base de dados relacionada a variável de configuração <i>ASPNETCORE_IDENTITY_SERVER_BD</i>.

A chamada ao método <i>AddIdentity</i> adiciona o serviço de autenticação e autorização de usuários  do <i>framework</i> <b>IdentityServer4</b> a aplicação, configurando a utilização das estruturas <b>Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityUser</b> e <b>Microsoft.AspNetCore.Identity.EntityFrameworkCore.IdentityRole</b> para armazenamento de usuários e roles através da base de dados criada e referenciada pela classe <b>AspnetCoreIdentityDbContext</b> com a utilização de geração de <i>tokens</i> padrão para alteração de senha, e-mail, telefone, etc do usuário.

A chamada ao método <i>Configure</i> define que será necessário informar um e-mail único para o cadastro de cada usuário.

Ao término destas alterações o <i>framework</i> <b>IdentityServer4</b> já estará configurado para o uso.

### Funcionamento básico do o <i>framework</i> <b>IdentityServer4</b>
O <i>framework</i> <b>IdentityServer4</b> faz uso das seguintes estruturas de banco de dados para o gerenciamento dos usuários:

1. AspNetUsers - Armazena os usuários
1. AspNetRoles - Armazena os Roles
1. AspNetRoleClaims - Armazena os claims relacionados aos roles
1. AspNetUserRoles - Armazena os roles relacionados aos claims
1. AspNetUserClaims - Armazena os claims relacionados aos usuários
1. AspNetUserTokens - Armazena os tokens de autorização externa
1. AspNetUserLogins - Armazena os dados de login feitos utilizando bibliotecas de terceiros como o Google, Facebook, etc

O <i>framework</i>, ao ser configurado, disponibiliza via injeção de dependência as seguintes classes para a manipulação e execução de tarefas determinadas pelo mesmo:

1. Microsoft.AspNetCore.Identity.UserManager - Gerencia as operações relacionados ao usuário
1. Microsoft.AspNetCore.Identity.RoleManager - Gerencia as operações relacionados aos Roles
1. Microsoft.AspNetCore.Identity.SignInManager - Gerencia as operações relacionados ao processo de SingIn

### Criar serviço para gerenciamento de acesso aos dados mantidos pelo <i>framework</i> <b>IdentityServer4</b>

Criar a exceção IdentityServiceException para a identificação de erros gerados por operações do <i>framework</i> <b>IdentityServer4</b>: 

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

Criar a classe IdentityService.cs conforme código abaixo:

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

Esta classe permitira a aplicação inserir dados básicos na base referenciada pelo <i>framework</i> <b>IdentityServer4</b> através do método <i>Inicializar</i>. O mesmo irá inserir dois roles, um usuário e relacionar este a um dos roles inseridos. 

A classe também oferece métodos para obtenção dos roles associados aos usuários e das claims associadas aos roles e usuários através dos métodos <i>ObterClaims</i> e <i>ObterRoles</i>.

Para a autenticação do usuário é disponibilizado o método <i>AutenticarUsuario</i>.


### Criar <i>controller</i> <b>AspNetCore MVC</b> para disponibilização de método de login que retorne um token JWT

Através dos métodos disponibilizados pela classe IdentityService iremos construir um método REST para o login de um usuário, que valide a senha e a <i>audience</i> deste, e que retorne um token JWT que contenha os seguintes claims devidamente preenchidos:

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
1. Claims relacionados aos roles e usuários gerenciados pelo <i>framework</i> <b>IdentityServer4</b>

Para tanto será necessário criar uma classe <b>DTO</b> com os dados necessários ao login conforme código abaixo:

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


Criar a classe LoginController conforme código abaixo:

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

Podemos agora adicionar este serviço ao ServiceProvider através da adição do trecho de código abaixo ao método <i>ConfigureServices</i> da classe <i>Startup</i>

```csharp
services.AddTransient(typeof(IdentityService));
``` 

Podemos também garantir a chamada ao método de inicialização dos dados básicos com o seguinte trecho de código inserido no método <i>Configure</i> da classe <i>Startup</i> 

```csharp
IServiceScopeFactory serviceScopeFactory = (IServiceScopeFactory) app.ApplicationServices.GetService(typeof(IServiceScopeFactory));

using (IServiceScope scope = serviceScopeFactory.CreateScope())
{
    IServiceProvider services = scope.ServiceProvider;
    services.GetRequiredService<IdentityService>().Inicializar();
}
``` 

#### Adicionar as configurações necessárias para a criação do token JWT ao arquivo appsettings.json

Adicionar as configuração abaixo ao arquivo <i>appsettings.json</i>

Estas definem a chave simétrica utilizada para gerar o token, o <i>issuer</i>, as <i>audiences</i> válidas e o tempo de expiração do token em mile segundos.

<b>Necessário lembrar que para a execução desta aplicação é necessário que a data/hora da máquina tenha como fuso horário o valor UTC - Tempo Universal Coordenado.</b>

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

Agora podemos acessar o método de login através do sítio <http://localhost:6000/api/Login> passando no body da requisição o texto json abaixo (application/json):

```json
{
	"Audience": "audience1",
	"UserEmail": "admin@serpro.gov.br",
	"UserPassword": "Sw0rdfi$h"
} 
```

Deveremos ter uma resposta similar ao texto/json abaixo:

```json
{
    "Authorized": true,
    "Created": "2019-04-17 17:44:10.4575850Z",
    "Expires": "2019-04-18 03:54:10.4575850Z",
    "AccessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6WyIwMjlhZDAyNi1mZDZlLTQyMDctOTA5YS1mNzhjNjBmN2JlZjciLCJhZG1pbkBzZXJwcm8uZ292LmJyIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjAwMC8iLCJqdGkiOiIyNGZiMjEzNzg4MDY0MGZlYTA4NTQ2ZTBlNDhkZTQxMyIsInN1YiI6IjAyOWFkMDI2LWZkNmUtNDIwNy05MDlhLWY3OGM2MGY3YmVmNyIsImVtYWlsIjoiYWRtaW5Ac2VycHJvLmdvdi5iciIsImV4cCI6MTU1NTU1OTY1MCwibmJmIjoxNTU1NTIzMDUwLCJhdXRoX3RpbWUiOiIxNTU1NTIzMDUwIiwiYXVkIjoiYXVkaWVuY2UxIiwicm9sZSI6ImFkbWluaXN0cmFkb3IiLCJpYXQiOjE1NTU1MjMwNTB9.UR0XLqutQWhwPkSzcilwt-Yr2XD6Cvf11kpg8ZB3xxk"
}
```
