using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;

using FredrikHr.PowerPlatformCustomDelegation.Entities;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public sealed class KeyVaultBackedCredentialsSource
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

    public static async Task<KeyVaultBackedCredentialsSource?> FromParameterCollectionAsync(
        ParameterCollection inputs,
        PluginExecutionInformation executionInformation,
        AzureUtility azureUtility,
        string credsSourceInputParameterName)
    {
        _ = inputs ?? throw new ArgumentNullException(nameof(inputs));
        _ = executionInformation ?? throw new ArgumentNullException(nameof(executionInformation));
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;

        if (inputs.TryGetValue(
            credsSourceInputParameterName,
            out Entity? credsSourceEntityInput) &&
            credsSourceEntityInput is not null)
        {
            switch (credsSourceEntityInput.LogicalName)
            {
                case string n2
                when KeyVaultReference.EntityLogicalName.Equals(n2, cmp)
                && credsSourceEntityInput is not KeyVaultReference:
                    credsSourceEntityInput = credsSourceEntityInput.ToEntity<KeyVaultReference>();
                    break;
                case string n2
                when az_keyvaultreference.EntityLogicalName.Equals(n2, cmp)
                && credsSourceEntityInput is not az_keyvaultreference:
                    credsSourceEntityInput = credsSourceEntityInput.ToEntity<az_keyvaultreference>();
                    break;
            }
        }

        EnsureExpandCredentialsSourceEntity(
            executionInformation.SystemDataverseClient,
            ref credsSourceEntityInput);
        inputs[credsSourceInputParameterName] = credsSourceEntityInput;

        KeyVaultBackedCredentialsSource? credsSource = credsSourceEntityInput switch
        {
            KeyVaultReference kvRef => ConstructFromKeyVaultReference(kvRef),
            az_keyvaultreference kvRef => ConstructFromAzKeyVaultReference(kvRef),
            _ => null,
        };
        if (credsSource is not null)
        {
            await credsSource.FillMissingPropertiesAsync(azureUtility)
                .ConfigureAwait(continueOnCapturedContext: false);
        }
        return credsSource;

        static KeyVaultBackedCredentialsSource ConstructFromKeyVaultReference(
            KeyVaultReference kvRef)
        {
            string? kvUrl = kvRef.KeyVaultUri;
            Uri? kvUri = kvUrl is not null ? new(kvUrl, UriKind.Absolute) : null;
            KeyVaultBackedCredentialsSource source = new()
            {
                KeyVaultUri = kvUri,
                KeyVaultName = kvUri is not null ? AzureUtility.GetKeyVaultNameFromUri(kvUri) : null,
                KeyVaultObjectType = kvRef.KeyType.GetValueOrDefault(),
                KeyVaultObjectName = kvRef.KeyName,
            };
            return source;
        }

        static KeyVaultBackedCredentialsSource ConstructFromAzKeyVaultReference(
            az_keyvaultreference kvRef)
        {
            string? kvUrl = kvRef.az_vaulturi;
            Uri? kvUri = kvUrl is not null ? new(kvUrl, UriKind.Absolute) : null;
            string? kvArmId = kvRef.az_resourceid;
            KeyVaultBackedCredentialsSource source = new()
            {
                KeyVaultUri = kvUri,
                KeyVaultName = kvUri is not null ? AzureUtility.GetKeyVaultNameFromUri(kvUri) : null,
                KeyVaultObjectName = kvRef.az_name,
                KeyVaultObjectType = kvRef.az_type.GetValueOrDefault() switch
                {
                    az_keyvaultdataobjecttype.Secret => keytype.Secret,
                    az_keyvaultdataobjecttype.Certificate => keytype.Certificate,
                    az_keyvaultdataobjecttype.CertificatewithX509chain => keytype.CertificateWithX5c,
                    _ => default,
                },
                KeyVaultObjectVersion = kvRef.az_version,
                KeyVaultObjectResourceIdentifier = kvArmId is not null
                    ? ResourceIdentifier.Parse(kvArmId)
                    : null,
            };
            if (kvRef.az_vaultobjectiduri is string kvObjIdUrl)
            {
                Uri kvObjIdUri = new(kvObjIdUrl, UriKind.Absolute);
                switch (source.KeyVaultObjectType)
                {
                    case keytype.Secret:
                        source.KeyVaultSecretIdentifier = new(kvObjIdUri);
                        break;
                    case keytype.Certificate:
                    case keytype.CertificateWithX5c:
                        source.KeyVaultCertificateIdentifier = new(kvObjIdUri);
                        break;
                }
            }
            return source;
        }
    }

    private static void EnsureExpandCredentialsSourceEntity(
        IOrganizationService dataverseClient,
        ref Entity? sourceEntity)
    {
        switch (sourceEntity)
        {
            case KeyVaultReference kvRef
            when IsKeyVaultReferenceEntityExpandable(kvRef):
                sourceEntity = RetrieveEntity(dataverseClient, kvRef, KeyVaultReference.ColumnSet);
                break;
            case az_keyvaultreference kvRef
            when IsAzureKeyVaultReferenceEntityExpandable(kvRef):
                sourceEntity = RetrieveEntity(dataverseClient, kvRef, az_keyvaultreference.ColumnSet);
                break;
        }

        static bool IsKeyVaultReferenceEntityExpandable(KeyVaultReference kvRef)
        {
            return kvRef.KeyVaultReferenceId.HasValue &&
                (!kvRef.KeyType.HasValue ||
                string.IsNullOrEmpty(kvRef.KeyVaultUri) ||
                string.IsNullOrEmpty(kvRef.KeyName));
        }

        static bool IsAzureKeyVaultReferenceEntityExpandable(az_keyvaultreference kvRef)
        {
            if (!kvRef.az_keyvaultreferenceId.HasValue) return false;
            if (kvRef.az_type.HasValue)
            {
                if (!string.IsNullOrEmpty(kvRef.az_vaulturi) &&
                    !string.IsNullOrEmpty(kvRef.az_name))
                    return false;
                if (!string.IsNullOrEmpty(kvRef.az_vaultobjectiduri))
                    return false;
            }
            return true;
        }

        static T RetrieveEntity<T>(
            IOrganizationService dataverseClient,
            T entity,
            Microsoft.Xrm.Sdk.Query.ColumnSet columnSet)
            where T: Entity
        {
            return dataverseClient.Retrieve(entity.LogicalName, entity.Id, columnSet) switch
            {
                T e => e,
                Entity e => e.ToEntity<T>(),
            };
        }
    }

    public async Task FillMissingPropertiesAsync(AzureUtility azureUtility)
    {
        if (azureUtility is null) return;

        switch (KeyVaultObjectType)
        {
            case keytype.Secret
            when KeyVaultSecretIdentifier is KeyVaultSecretIdentifier kvSecretId:
                (KeyVaultUri, KeyVaultObjectName, KeyVaultObjectVersion) =
                    (kvSecretId.VaultUri, kvSecretId.Name, kvSecretId.Version);
                break;
            case keytype.Certificate:
            case keytype.CertificateWithX5c:
                if (KeyVaultCertificateIdentifier is not KeyVaultCertificateIdentifier kvCertId)
                    break;
                (KeyVaultUri, KeyVaultObjectName, KeyVaultObjectVersion) =
                    (kvCertId.VaultUri, kvCertId.Name, kvCertId.Version);
                break;
        }
        if (KeyVaultName is string kvName &&
            KeyVaultUri is null)
        {
            KeyVaultUri = new($"https://{kvName}.vault.azure.net", UriKind.Absolute);
        }
        if (KeyVaultUri is Uri kvUri)
        {
            KeyVaultName ??= AzureUtility.GetKeyVaultNameFromUri(kvUri);
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