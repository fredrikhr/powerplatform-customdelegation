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

    public async Task FillMissingPropertiesAsync(AzureUtility azureUtility)
    {
        if (azureUtility is null) return;

        if (KeyVaultName is string kvName &&
            KeyVaultUri is null)
        {
            KeyVaultUri = new($"https://{kvName}.vault.azure.net", UriKind.Absolute);
        }
        if (KeyVaultUri is Uri kvUri)
        {
            KeyVaultResourceIdentifier ??= await azureUtility
                .GetKeyVaultResourceIdentifier(kvUri)
                .ConfigureAwait(continueOnCapturedContext: false);
            if (KeyVaultResourceIdentifier is ResourceIdentifier kvArmId &&
                KeyVaultObjectName is string kvObjName)
            {
                switch (KeyVaultObjectType)
                {
                    case keytype.Secret:
                        KeyVaultSecretIdentifier kvSecretUriId = KeyVaultSecretIdentifier ??=
                            KeyVaultPluginUtility.GetKeyVaultSecretIdentifier(kvUri, kvObjName, KeyVaultObjectVersion);
                        KeyVaultObjectResourceIdentifier ??= AzureUtility
                            .GetKeyVaultResourceIdentifier(kvArmId, kvSecretUriId);
                        break;
                    case keytype.Certificate:
                    case keytype.CertificateWithX5c:
                        KeyVaultCertificateIdentifier kvCertUriId = KeyVaultCertificateIdentifier ??=
                            KeyVaultPluginUtility.GetKeyVaultCertificateIdentifier(kvUri, kvObjName, KeyVaultObjectVersion);
                        KeyVaultObjectResourceIdentifier ??= AzureUtility
                            .GetKeyVaultResourceIdentifier(kvArmId, kvCertUriId);
                        break;
                }
            }
        }
    }
}