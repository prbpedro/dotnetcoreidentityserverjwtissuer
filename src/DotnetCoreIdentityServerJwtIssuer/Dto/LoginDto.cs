namespace DotnetCoreIdentityServerJwtIssuer.Dto
{
    public class LoginDto
    {
        public string Audience {get; set;}

        public string UserEmail {get; set;}

        public string UserPassword {get; set;}
    }
}