using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Identity.Client;
using Microsoft.Xrm.Sdk.Query;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;
using FredrikHr.PowerPlatformCustomDelegation.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public sealed class MsalPluginUtility
{
    public const string FallbackClientId = "00000007-0000-0000-c000-000000000000";
    internal static class InputParameterNames
    {
        internal const string Application = nameof(Application);
        internal const string ApplicationEntity = nameof(ApplicationEntity);
        internal const string ClientCredentialsSource = nameof(ClientCredentialsSource);
        internal const string ClientCredentialsSourceEntity = nameof(ClientCredentialsSourceEntity);
    }

    private readonly IServiceProvider _serviceProvider;
    private readonly ParameterCollection _inputs;
    private readonly PluginExecutionInformation _executionInformation;
    private readonly AzureUtility _azureUtility;
    private readonly Lazy<bool> _isApplicationSelfRequest;
    private readonly Lazy<bool> _isPluginIdentityRequest;
    private readonly Lazy<ConfidentialClientApplicationOptions?> _msalClientOptions;
    private readonly Lazy<PluginClientCredentialsSource?> _clientCredentialsSource;

    public MsalPluginUtility(
        IServiceProvider serviceProvider,
        PluginExecutionInformation executionInformation,
        AzureUtility azureUtility)
    {
        _serviceProvider = serviceProvider;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        _inputs = context.InputParameters;
        _executionInformation = executionInformation;
        _azureUtility = azureUtility;

        _isApplicationSelfRequest = new(EvaluateIsApplicationSelfRequest);
        _isPluginIdentityRequest = new(EvaluateIsApplicationPluginIdentityRequest);
        _msalClientOptions = new(ConstructConfidentialClientApplicationOptions);
        _clientCredentialsSource = new(ConstructClientCredentialsSource);
    }

    public bool IsApplicationRequestingSelf => _isApplicationSelfRequest.Value;
    public bool IsRequestedApplicationPluginIdentity => _isPluginIdentityRequest.Value;
    public ConfidentialClientApplicationOptions? MsalClientOptions => _msalClientOptions.Value;
    public PluginClientCredentialsSource? ClientCredentialsSource => _clientCredentialsSource.Value;

    public ConfidentialClientApplicationBuilder CreateMsalClientBuilder()
    {
        var builder = ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(MsalClientOptions);

        if (_inputs.TryGetValue(
            InputParameterNames.ApplicationEntity,
            out oauth2_clientidreference? oauth2Reference) &&
            oauth2Reference is not null)
        {
            string? instanceDiscoveryJson = oauth2Reference.msal_instancediscoveryjson;
            if (string.IsNullOrEmpty(instanceDiscoveryJson) &&
                oauth2Reference.oidc_authorityurl is string oidcAuthorityUrl)
            {
                instanceDiscoveryJson = $$"""
                    { "tenant_discovery_endpoint": "{{oidcAuthorityUrl}}/.well-known/openid-configuration" }
                    """;
            }
            builder = builder.WithInstanceDiscoveryMetadata(instanceDiscoveryJson);
        }

        if (ClientCredentialsSource is PluginClientCredentialsSource credentialsSource)
        {
            string? customKeyIdentifier = credentialsSource.CustomKeyIdentifier;
            bool sendX5c = false;
            switch (credentialsSource.KeyVaultObjectType)
            {
                case keytype.Secret:
                    KeyVaultSecretIdentifier keyVaultSecretIdentifier =
                        credentialsSource.KeyVaultSecretIdentifier
                        ?? throw new InvalidOperationException("KeyVaultSecretIdentifier is null");
                    SecretClient keyVaultSecretClient = new(
                        keyVaultSecretIdentifier.VaultUri,
                        _azureUtility.TokenCredential
                        );
                    KeyVaultSecret keyVaultSecret = keyVaultSecretClient
                        .GetSecret(
                            keyVaultSecretIdentifier.Name,
                            keyVaultSecretIdentifier.Version
                            );
                    builder = builder.WithClientSecret(keyVaultSecret.Value);
                    break;
                case keytype.Certificate:
                    var clientAssertionProvider = KeyVaultPluginUtility
                        .GetKeyVaultCertificateAssertionProvider(
                            _azureUtility.TokenCredential,
                            credentialsSource.KeyVaultCertificateIdentifier
                            ?? throw new InvalidOperationException("KeyVaultCertificateIdentifier is null"),
                            customKeyIdentifier,
                            sendX5c: sendX5c
                            );
                    builder = builder.WithClientAssertion(clientAssertionProvider);
                    break;
                case keytype.CertificateWithX5c:
                    sendX5c = true;
                    goto case keytype.Certificate;
            }
        }

        return builder;
    }

    private ConfidentialClientApplicationOptions? ConstructConfidentialClientApplicationOptions()
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;
        var context = _serviceProvider.Get<IPluginExecutionContext6>();
        var idpAuthorityInfo = _serviceProvider.Get<IEnvironmentService>();
        Uri idpInstanceUri = idpAuthorityInfo.AzureAuthorityHost;
        string idpInstanceUrl = idpInstanceUri.ToString();

        Entity? applicationEntityInput;
        if (_inputs.TryGetValue(
            InputParameterNames.Application,
            out EntityReference applicationEntityReference))
        {
            _inputs[InputParameterNames.ApplicationEntity] = applicationEntityReference.LogicalName switch
            {
                string n1 when ManagedIdentity.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<ManagedIdentity>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        ManagedIdentity.ColumnSet
                        ),
                string n1 when SystemUser.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<SystemUser>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        SystemUser.ApplicationUserColumnSet
                        ),
                string n1 when ApplicationUser.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<ApplicationUser>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        ApplicationUser.ColumnSet
                        ),
                string n1 when entra_serviceprincipalreference.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<entra_serviceprincipalreference>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        entra_serviceprincipalreference.ColumnSet
                        ),
                string n1 when oauth2_clientidreference.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<oauth2_clientidreference>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        oauth2_clientidreference.ColumnSet
                        ),
                _ => throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{applicationEntityReference.LogicalName}' specified for {InputParameterNames.Application}, but only the following entities are allowed: {ManagedIdentity.EntityLogicalName}, {SystemUser.EntityLogicalName}, {ApplicationUser.EntityLogicalName}, {entra_serviceprincipalreference.EntityLogicalName}, {oauth2_clientidreference.EntityLogicalName}"
                    ),
            };
        }
        if (_inputs.TryGetValue(
            InputParameterNames.ApplicationEntity,
            out applicationEntityInput) &&
            applicationEntityInput is not null)
        {
            switch (applicationEntityInput.LogicalName)
            {
                case string n
                when ManagedIdentity.EntityLogicalName.Equals(n, cmp)
                && applicationEntityInput is not ManagedIdentity:
                    applicationEntityInput = applicationEntityInput.ToEntity<ManagedIdentity>();
                    break;
                case string n
                when SystemUser.EntityLogicalName.Equals(n, cmp)
                && applicationEntityInput is not SystemUser:
                    applicationEntityInput = applicationEntityInput.ToEntity<SystemUser>();
                    break;
                case string n
                when ApplicationUser.EntityLogicalName.Equals(n, cmp)
                && applicationEntityInput is not ApplicationUser:
                    applicationEntityInput = applicationEntityInput.ToEntity<ApplicationUser>();
                    break;
                case string n
                when entra_serviceprincipalreference.EntityLogicalName.Equals(n, cmp)
                && applicationEntityInput is not entra_serviceprincipalreference:
                    applicationEntityInput = applicationEntityInput.ToEntity<entra_serviceprincipalreference>();
                    break;
                case string n
                when oauth2_clientidreference.EntityLogicalName.Equals(n, cmp)
                && applicationEntityInput is not oauth2_clientidreference:
                    applicationEntityInput = applicationEntityInput.ToEntity<oauth2_clientidreference>();
                    break;
            }
        }
        if (applicationEntityInput is null &&
            _executionInformation.ApplicationSystemUser is SystemUser user)
            applicationEntityInput = user;

        return applicationEntityInput switch
        {
            ManagedIdentity mi => ConstructFromManagedIdentity(mi),
            SystemUser su => ConstructFromSystemUser(su),
            ApplicationUser au => ConstructFromApplicationUser(au),
            entra_serviceprincipalreference spnRef => ConstructFromEntraServicePrincipalReference(spnRef),
            oauth2_clientidreference oauth2Ref => ConstructFromOAuthClientIdReference(oauth2Ref),
            _ => null,
        };

        ConfidentialClientApplicationOptions ConstructFromEntraServicePrincipalReference(
            entra_serviceprincipalreference entraSpnRef
            )
        {
            ConfidentialClientApplicationOptions opts = new()
            {
                ClientId = entraSpnRef.entra_clientid,
                ClientName = entraSpnRef.entra_displayname,
                TenantId = entraSpnRef.entra_tenant,
            };
            switch (entraSpnRef.entra_instance)
            {
                case msal_azurecloudinstance.Public:
                    opts.AzureCloudInstance = AzureCloudInstance.AzurePublic;
                    break;
                case msal_azurecloudinstance.China:
                    opts.AzureCloudInstance = AzureCloudInstance.AzureChina;
                    break;
                case msal_azurecloudinstance.Germany:
                    opts.AzureCloudInstance = AzureCloudInstance.AzureGermany;
                    break;
                case msal_azurecloudinstance.UsGovernment:
                    opts.AzureCloudInstance = AzureCloudInstance.AzureUsGovernment;
                    break;
                default:
                case null:
                case msal_azurecloudinstance.Automatic:
                    opts.Instance = idpInstanceUrl;
                    break;
            }
            if (string.IsNullOrEmpty(opts.TenantId))
                opts.TenantId = context.TenantId.ToString();
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromOAuthClientIdReference(
            oauth2_clientidreference oauth2Ref
            )
        {
            ConfidentialClientApplicationOptions opts = new()
            {
                ClientId = oauth2Ref.oauth2_clientid,
                ClientName = oauth2Ref.oauth2_displayname,
            };
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromManagedIdentity(
            ManagedIdentity managedIdentity
            )
        {
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = (managedIdentity.TenantId switch
                {
                    Guid g => g != Guid.Empty ? g : context.TenantId,
                    null => context.TenantId,
                }).ToString(),
                ClientId = managedIdentity.ApplicationId?.ToString(),
                ClientName = managedIdentity.Name ?? $"{ManagedIdentity.EntitySetName}({managedIdentity.Id})",
            };
            if (managedIdentity.KeyVaultReferenceId is EntityReference miCreds &&
                (!_inputs.TryGetValue<EntityReference?>(
                    InputParameterNames.ClientCredentialsSource,
                    out var overrideCreds
                ) || overrideCreds is null))
            {
                _inputs[InputParameterNames.ClientCredentialsSource] =
                    miCreds;
            }
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromSystemUser(SystemUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but referenced entity does not represent an application user."
                    );
            }
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = context.TenantId.ToString(),
                ClientId = appId.ToString(),
                ClientName = applicationUser.FullName,
            };
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromApplicationUser(ApplicationUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but referenced entity does not represent an application user."
                    );
            }
            ConfidentialClientApplicationOptions opts = new()
            {
                Instance = idpInstanceUrl,
                TenantId = context.TenantId.ToString(),
                ClientId = appId.ToString(),
                ClientName = applicationUser.ApplicationName,
            };
            return opts;
        }
    }

    private bool EvaluateIsApplicationSelfRequest()
    {
        var context = _serviceProvider.Get<IPluginExecutionContext6>();
        SystemUser? callingApplicationUser = _executionInformation.ApplicationSystemUser;
        ConfidentialClientApplicationOptions? msalOptions =
            MsalClientOptions;
        if (callingApplicationUser is not null &&
            msalOptions is not null &&
            string.Equals(
                callingApplicationUser.ApplicationId?.ToString(),
                msalOptions.ClientId,
                StringComparison.OrdinalIgnoreCase
                ) &&
            string.Equals(
                context.TenantId.ToString(),
                msalOptions.TenantId,
                StringComparison.OrdinalIgnoreCase
                ))
        {
            // Calling user and requested application identity are equal
            return true;
        }

        return false;
    }

    private bool EvaluateIsApplicationPluginIdentityRequest()
    {
        ManagedIdentity? pluginIdentity = _executionInformation.PluginManagedIdentity;
        ConfidentialClientApplicationOptions? msalOptions = MsalClientOptions;
        if (pluginIdentity is not null &&
            msalOptions is not null &&
            string.Equals(
                pluginIdentity.ApplicationId?.ToString(),
                msalOptions.ClientId,
                StringComparison.OrdinalIgnoreCase
                ) &&
            string.Equals(
                pluginIdentity.TenantId?.ToString(),
                msalOptions.TenantId,
                StringComparison.OrdinalIgnoreCase
                ))
        {
            // Plugin identity and requested application identity are equal
            return true;
        }

        return false;
    }

    private PluginClientCredentialsSource? ConstructClientCredentialsSource()
    {
        const StringComparison cmp = StringComparison.OrdinalIgnoreCase;

        // Force evaluation of MSAL Client Options
        // might set Client Credentials Source inputs during evaluation
        _ = MsalClientOptions;

        if (_inputs.TryGetValue(
            InputParameterNames.ClientCredentialsSource,
            out EntityReference credsSourceEntityRef))
        {
            _inputs[InputParameterNames.ClientCredentialsSourceEntity] =
                credsSourceEntityRef.LogicalName switch
            {
                string n1 when KeyVaultReference.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<KeyVaultReference>(
                        _executionInformation.SystemDataverseClient,
                        credsSourceEntityRef,
                        KeyVaultReference.ColumnSet
                        ),
                string n1 when az_keyvaultreference.EntityLogicalName.Equals(n1, cmp)
                    => GetByEntityReference<az_keyvaultreference>(
                        _executionInformation.SystemDataverseClient,
                        credsSourceEntityRef,
                        az_keyvaultreference.ColumnSet
                        ),
                _ => throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{credsSourceEntityRef.LogicalName}' specified for {InputParameterNames.ClientCredentialsSource}, but only the following entities are allowed: {KeyVaultReference.EntityLogicalName}, {az_keyvaultreference.EntityLogicalName}"
                    ),
            };
        }
        if (_inputs.TryGetValue(
            InputParameterNames.ClientCredentialsSourceEntity,
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

        return credsSourceEntityInput switch
        {
            KeyVaultReference kvRef => ConstructFromKeyVaultReference(kvRef),
            az_keyvaultreference kvRef => ConstructFromAzKeyVaultReference(kvRef),
            _ => null,
        };

        PluginClientCredentialsSource ConstructFromKeyVaultReference(
            KeyVaultReference kvRef)
        {
            string? kvUrl = kvRef.KeyVaultUri;
            Uri? kvUri = kvUrl is not null ? new(kvUrl, UriKind.Absolute) : null;
            PluginClientCredentialsSource source = new()
            {
                KeyVaultUri = kvUri,
                KeyVaultName = kvUri is not null ? AzureUtility.GetKeyVaultNameFromUri(kvUri) : null,
                KeyVaultObjectType = kvRef.KeyType.GetValueOrDefault(),
                KeyVaultObjectName = kvRef.KeyName,
            };
            return source;
        }

        PluginClientCredentialsSource ConstructFromAzKeyVaultReference(
            az_keyvaultreference kvRef)
        {
            string? kvUrl = kvRef.az_vaulturi;
            Uri? kvUri = kvUrl is not null ? new(kvUrl, UriKind.Absolute) : null;
            string? kvArmId = kvRef.az_resourceid;
            PluginClientCredentialsSource source = new()
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

    public void EnsureMsalConfidentialClientIsAuthorized(
        PluginClientCredentialsSource? credentialsSource = null)
    {
        var context = _serviceProvider.Get<IPluginExecutionContext2>();
        if (!IsApplicationRequestingSelf &&
            !_executionInformation.UserHasImpersonationPrivilege)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required privilege '{PluginExecutionInformation.PrivilegeNameImpersonation}'."
                );
        }

        if (IsRequestedApplicationPluginIdentity)
        {
            return;
        }

        if (MsalClientOptions is null)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the application for which an access token should be acquired."
                );
        }

        credentialsSource ??= ClientCredentialsSource;
        credentialsSource?.FillMissingPropertiesAsync(_azureUtility)
            .GetAwaiter().GetResult();
        if (credentialsSource is not { KeyVaultObjectResourceIdentifier: ResourceIdentifier kvObjArmId })
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the credential source from Key Vault to authenticate the requested application identity."
                );
        }

        KeyVaultDataAccessEvaluator kvAccessEval = new(
            _azureUtility.ArmClient,
            kvObjArmId,
            context.UserAzureActiveDirectoryObjectId
            );
        KeyVaultDataAccessPermisions kvAccessPerms = kvAccessEval
            .EvaluateAccessAsync()
            .GetAwaiter().GetResult();
        switch (credentialsSource.KeyVaultObjectType)
        {
            case keytype.Secret
            when !kvAccessPerms.HasFlag(KeyVaultDataAccessPermisions.GetSecret):
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.Forbidden,
                    message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required role assignment to use the specified Key Vault Secret as a credential for application authentication. User is not authorized for the Get Secret Key Vault action on the specified secret."
                    );
            case keytype.Certificate
            when !kvAccessPerms.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties | KeyVaultDataAccessPermisions.SignWithKey):
            case keytype.CertificateWithX5c
            when !kvAccessPerms.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties | KeyVaultDataAccessPermisions.SignWithKey):
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.Forbidden,
                    message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required role assignment to use the specified Key Vault Certificate as a credential for application authentication. User is not authorized either for the Get Certificate Properties og Sign action on the specified certificate."
                    );
        }
    }

    private static T? GetByEntityReference<T>(
        IOrganizationService dataverseClient,
        EntityReference r,
        ColumnSet columnSet
        ) where T : Entity
    {
        return dataverseClient.Retrieve(r.LogicalName, r.Id, columnSet) switch
        {
            T t => t,
            Entity e => e.ToEntity<T>(),
            _ => null,
        };
    }
}
