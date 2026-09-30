using System.Text.RegularExpressions;

using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public sealed class AzureUtility(TokenCredential azureCredential)
{
    public ArmClient ArmClient => field ??= new(TokenCredential);

    public TokenCredential TokenCredential { get; } = azureCredential;

    private static readonly Regex KeyVaultNameRegex = new("""
        ^[^\.]+
        """,
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static string? GetKeyVaultNameFromUri(Uri keyVaultUri)
    {
        string hostname = keyVaultUri.Host;
        return KeyVaultNameRegex.Match(hostname)?.Value;
    }

    public async Task<ResourceIdentifier?> GetKeyVaultResourceIdentifier(
        Uri keyVaultUri)
    {
        string? keyVaultName = GetKeyVaultNameFromUri(keyVaultUri);
        await foreach (SubscriptionResource subscr in ArmClient.GetSubscriptions().ConfigureAwait(continueOnCapturedContext: false))
        {
            await foreach (KeyVaultResource keyvault in subscr.GetKeyVaultsAsync().ConfigureAwait(continueOnCapturedContext: false))
            {
                if (string.Equals(keyVaultName, keyvault.Data.Name, StringComparison.OrdinalIgnoreCase))
                {
                    return keyvault.Id;
                }
            }
        }
        return null;
    }

    public async Task<ResourceIdentifier?> GetKeyVaultResourceIdentifier(
        KeyVaultSecretIdentifier keyVaultSecretUriIdentifier)
    {
        ResourceIdentifier? keyVaultResourceId = await
            GetKeyVaultResourceIdentifier(keyVaultSecretUriIdentifier.VaultUri)
            .ConfigureAwait(continueOnCapturedContext: false);
        return keyVaultResourceId is null ? null :
            GetKeyVaultResourceIdentifier(
                keyVaultResourceId,
                keyVaultSecretUriIdentifier);
    }

    public static ResourceIdentifier GetKeyVaultResourceIdentifier(
        ResourceIdentifier keyVaultResourceId,
        KeyVaultSecretIdentifier keyVaultSecretUriIdentifier)
    {
        ResourceIdentifier keyVaultSecretArmId = keyVaultResourceId
            .AppendChildResource("secrets", keyVaultSecretUriIdentifier.Name);
        return keyVaultSecretArmId;
    }

    public async Task<ResourceIdentifier?> GetKeyVaultResourceIdentifier(
        KeyVaultCertificateIdentifier keyVaultCertUriIdentifier)
    {
        ResourceIdentifier? keyVaultResourceId = await
            GetKeyVaultResourceIdentifier(keyVaultCertUriIdentifier.VaultUri)
            .ConfigureAwait(continueOnCapturedContext: false);
        return keyVaultResourceId is null ? null :
            GetKeyVaultResourceIdentifier(
                keyVaultResourceId,
                keyVaultCertUriIdentifier);
    }

    public static ResourceIdentifier GetKeyVaultResourceIdentifier(
        ResourceIdentifier keyVaultResourceId,
        KeyVaultCertificateIdentifier keyVaultCertUriIdentifier)
    {
        ResourceIdentifier keyVaultSecretArmId = keyVaultResourceId
            .AppendChildResource("certificates", keyVaultCertUriIdentifier.Name);
        return keyVaultSecretArmId;
    }
}
