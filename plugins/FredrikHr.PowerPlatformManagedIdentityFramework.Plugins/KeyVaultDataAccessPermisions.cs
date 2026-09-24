namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

[Flags]
public enum KeyVaultDataAccessPermisions : int
{
    None = 0,
    GetSecret = 1,
    ReadCertificateProperties = 2,
    SignWithKey = 4,
}