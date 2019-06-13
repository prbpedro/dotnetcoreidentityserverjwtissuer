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

            if (
                    Configuration.GetSection("AppSettings:jwt:audiences").Get<string[]>().Contains(dto.Audience) &&
                    user != null
                )
            {
                var tokenString = BuildToken(user, dto.Audience, out string expirationDate, out string creationDate);

                response = Ok(
                new 
                { 
                    Authorized = true, 
                    Created = creationDate, 
                    Expires = expirationDate, 
                    AccessToken = tokenString 
                });

            }

            return response;
        }

        private string BuildToken(IdentityUser user, string audience, out string expirationDate, out string creationDate)
        {
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AppSettings:jwt:key"]));
            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            IList<string> userRoles = IdentityService.ObterRoles(user);
            IList<Claim> userClaims = IdentityService.ObterClaims(user);

            DateTime now = DateTime.UtcNow;
            DateTime expDateTime = now.AddMilliseconds(double.Parse(Configuration["AppSettings:jwt:millesecondsExp"])).ToUniversalTime();
            creationDate = now.ToString("yyyy-MM-dd HH:mm:ss.fffffffK");
            expirationDate = expDateTime.ToString("yyyy-MM-dd HH:mm:ss.fffffffK");
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
