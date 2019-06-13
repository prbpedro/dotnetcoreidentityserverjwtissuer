namespace DotnetCoreIdentityServerJwtIssuer.Persistencia
{

    public class ApplicationRoles
    {
        public const string ADMINISTRADOR = "administrador";

        public const string USUARIO = "usuario";

        public static readonly string[] VALUES = {ApplicationRoles.ADMINISTRADOR, ApplicationRoles.USUARIO};
    }
}