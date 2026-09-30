using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public sealed class PluginClientCredentialsSource
{
    public Uri? KeyVaultUri { get; set; }
    public string? KeyVaultName { get; set; }
    public keytype KeyVaultObjectType { get; set; }
    public string? KeyVaultObjectName { get; set; }
    public string? KeyVaultObjectVersion { get; set; }
    public ResourceIdentifier? KeyVaultResourceIdentifier { get; set; }
    public ResourceIdentifier? KeyVaultObjectResourceIdentifier { get; set; }
    public KeyVaultSecretIdentifier? KeyVaultSecretIdentifier { get; set; }
    public KeyVaultCertificateIdentifier? KeyVaultCertificateIdentifier { get; set; }
    public string? CustomKeyIdentifier { get; set; }
}