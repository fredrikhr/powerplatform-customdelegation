using Azure.Core;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Identity.Client;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;
using FredrikHr.PowerPlatformCustomDelegation.Entities;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

public sealed class MsalPluginUtility
{
    public const string FallbackClientId = "00000007-0000-0000-c000-000000000000";

    private readonly IServiceProvider _serviceProvider;
    private readonly ParameterCollection _inputs;
    private readonly string _applicationInputParameterName;
    private readonly string _credentialsSourceInputParameterName;
    private readonly string _clientConfigurationInputParameterName;
    private readonly PluginExecutionInformation _executionInformation;
    private readonly AzureUtility _azureUtility;
    private readonly Lazy<bool> _isApplicationSelfRequest;
    private readonly Lazy<bool> _isPluginIdentityRequest;
    private readonly Lazy<ConfidentialClientApplicationOptions?> _msalClientOptions;

    public MsalPluginUtility(
        IServiceProvider serviceProvider,
        PluginExecutionInformation executionInformation,
        AzureUtility azureUtility,
        string applicationInputParameterName,
        string credentialsSourceInputParameterName,
        string clientConfigurationInputParameterName)
    {
        _serviceProvider = serviceProvider;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        _executionInformation = executionInformation;
        _azureUtility = azureUtility;

        _inputs = context.InputParameters;
        _applicationInputParameterName = applicationInputParameterName;
        _credentialsSourceInputParameterName = credentialsSourceInputParameterName;
        _clientConfigurationInputParameterName = clientConfigurationInputParameterName;

        _isApplicationSelfRequest = new(EvaluateIsApplicationSelfRequest);
        _isPluginIdentityRequest = new(EvaluateIsApplicationPluginIdentityRequest);
        _msalClientOptions = new(ConstructConfidentialClientApplicationOptions);
    }

    private Task<KeyVaultBackedCredentialsSource?> ClientCredentialsSourceTask
        => field ?? ConstructClientCredentialsSource();
    public bool IsApplicationRequestingSelf => _isApplicationSelfRequest.Value;
    public bool IsRequestedApplicationPluginIdentity => _isPluginIdentityRequest.Value;
    public ConfidentialClientApplicationOptions? MsalClientOptions => _msalClientOptions.Value;
    public KeyVaultBackedCredentialsSource? ClientCredentialsSource =>
        ClientCredentialsSourceTask.GetAwaiter().GetResult();

    private void EnsureTranslateClientConfigurationInputParameter()
    {
        Entity? credsSourceEntityInput = null;
        if (_inputs.TryGetValue(
            _applicationInputParameterName,
            out Entity? applicationEntityInput
            ) && applicationEntityInput is not null &&
            _inputs.TryGetValue(
            _credentialsSourceInputParameterName,
            out credsSourceEntityInput
            ) && credsSourceEntityInput is not null)
        {
            return;
        }

        if (!_inputs.TryGetValue(
            _clientConfigurationInputParameterName,
            out EntityReference? configEntityReference
            ) || configEntityReference is null)
        {
            return;
        }
        var configEntity = _executionInformation.SystemDataverseClient
            .GetByEntityReference<msal_confidentialclientconfiguration>(
                configEntityReference, msal_confidentialclientconfiguration.ColumnSet);
        if (configEntity is null)
        {
            return;
        }

        if (applicationEntityInput is null &&
            configEntity.msal_clientinfoid is EntityReference applicationEntityReference)
        {
            applicationEntityInput = new Entity(
                applicationEntityReference.LogicalName,
                applicationEntityReference.Id);
            _inputs[_applicationInputParameterName] = applicationEntityInput;
        }
        if (credsSourceEntityInput is null &&
            configEntity.msal_clientcredentialsid is EntityReference credsSourceEntityReference)
        {
            credsSourceEntityInput = new Entity(
                credsSourceEntityReference.LogicalName,
                credsSourceEntityReference.Id);
            _inputs[_credentialsSourceInputParameterName] = credsSourceEntityInput;
        }
    }

    public ConfidentialClientApplicationBuilder CreateMsalClientBuilder()
    {
        var builder = ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(MsalClientOptions);

        if (_inputs.TryGetValue(
            _applicationInputParameterName,
            out oauth2_clientidreference? oauth2Reference) &&
            oauth2Reference is not null)
        {
            switch (oauth2Reference)
            {
                case { oidc_authorityurl: string oidcAuthority }:
                    builder = builder.WithOidcAuthority(oidcAuthority);
                    break;
                case { msal_instancediscoveryjson: string instanceDiscoveryMetadata }:
                    builder = builder.WithInstanceDiscoveryMetadata(instanceDiscoveryMetadata);
                    break;
            }
        }

        if (string.IsNullOrEmpty(MsalClientOptions?.ClientSecret) &&
            ClientCredentialsSource is KeyVaultBackedCredentialsSource credentialsSource)
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

        EnsureTranslateClientConfigurationInputParameter();

        if (_inputs.TryGetValue(
            _applicationInputParameterName,
            out Entity? applicationEntityInput) &&
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

        EnsureExpandApplicationEntity(
            _executionInformation.SystemDataverseClient,
            ref applicationEntityInput);
        _inputs[_applicationInputParameterName] = applicationEntityInput;

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
            entra_serviceprincipalreference entraSpnRef)
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
            oauth2_clientidreference oauth2Ref)
        {
            ConfidentialClientApplicationOptions opts = new()
            {
                ClientId = oauth2Ref.oauth2_clientid,
                ClientName = oauth2Ref.oauth2_displayname,
            };
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromManagedIdentity(
            ManagedIdentity managedIdentity)
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
            switch (managedIdentity)
            {
                case
                {
                    CredentialSource: credentialsource.ClientSecret,
                    ClientSecret: string clientSecretValue,
                }:
                    opts.ClientSecret = clientSecretValue;
                    break;
                case
                {
                    CredentialSource: credentialsource.KeyVault,
                    KeyVaultReferenceId: EntityReference miCredsReference,
                }
                when !_inputs.TryGetValue(
                    _credentialsSourceInputParameterName,
                    out Entity? overrideCreds) || overrideCreds is null:
                    Entity miCredsEntity = new(miCredsReference.LogicalName, miCredsReference.Id);
                    _inputs[_credentialsSourceInputParameterName] =
                        miCredsEntity;
                    break;
            }
            return opts;
        }

        ConfidentialClientApplicationOptions ConstructFromSystemUser(
            SystemUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {_applicationInputParameterName}, but it does not represent an application user."
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

        ConfidentialClientApplicationOptions ConstructFromApplicationUser(
            ApplicationUser applicationUser)
        {
            if (applicationUser is not { ApplicationId: Guid appId })
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {_applicationInputParameterName}, but its application ID is missing."
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

    private static void EnsureExpandApplicationEntity(
        IOrganizationService dataverseClient,
        ref Entity? applicationEntityInput)
    {
        switch (applicationEntityInput)
        {
            case ManagedIdentity mi
            when IsManagedIdentityEntityExpandable(mi):
                applicationEntityInput = RetrieveEntity(dataverseClient, mi, mi.ManagedIdentityId, ManagedIdentity.ColumnSet);
                break;
            case SystemUser su
            when IsSystemUserExandable(su):
                applicationEntityInput = RetrieveEntity(dataverseClient, su, su.SystemUserId, SystemUser.ApplicationUserColumnSet);
                break;
            case ApplicationUser au
            when IsApplicationUserExandable(au):
                applicationEntityInput = RetrieveEntity(dataverseClient, au, au.ApplicationUserId, ApplicationUser.ColumnSet);
                break;
            case entra_serviceprincipalreference spnRef
            when IsEntraServicePrincipalReferenceExandable(spnRef):
                applicationEntityInput = RetrieveEntity(dataverseClient, spnRef, spnRef.entra_serviceprincipalreferenceId, entra_serviceprincipalreference.ColumnSet);
                break;
            case oauth2_clientidreference oauth2Ref
            when IsOauth2ClientIdReferenceExandable(oauth2Ref):
                applicationEntityInput = RetrieveEntity(dataverseClient, oauth2Ref, oauth2Ref.oauth2_clientidreferenceId, oauth2_clientidreference.ColumnSet);
                break;
        }

        static bool IsManagedIdentityEntityExpandable(ManagedIdentity mi)
        {
            return mi.ManagedIdentityId.HasValue &&
                !mi.ApplicationId.HasValue;
        }

        static bool IsSystemUserExandable(SystemUser su)
        {
            return su.SystemUserId.HasValue &&
                !su.ApplicationId.HasValue;
        }

        static bool IsApplicationUserExandable(ApplicationUser au)
        {
            return au.ApplicationUserId.HasValue &&
                !au.ApplicationId.HasValue;
        }

        static bool IsEntraServicePrincipalReferenceExandable(
            entra_serviceprincipalreference spnRef)
        {
            return spnRef.entra_serviceprincipalreferenceId.HasValue &&
                string.IsNullOrEmpty(spnRef.entra_clientid);
        }

        static bool IsOauth2ClientIdReferenceExandable(
            oauth2_clientidreference oauth2Ref)
        {
            return oauth2Ref.oauth2_clientidreferenceId.HasValue &&
                string.IsNullOrEmpty(oauth2Ref.oauth2_clientid);
        }

        static T RetrieveEntity<T>(
            IOrganizationService dataverseClient,
            T entity,
            Guid? id,
            Microsoft.Xrm.Sdk.Query.ColumnSet columnSet)
            where T: Entity
        {
            return dataverseClient.Retrieve(entity.LogicalName, id ?? entity.Id, columnSet) switch
            {
                T e => e,
                Entity e => e.ToEntity<T>(),
            };
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

    private Task<KeyVaultBackedCredentialsSource?> ConstructClientCredentialsSource()
    {
        // Force evaluation of MSAL Client Options
        // might set Client Credentials Source inputs during evaluation
        _ = MsalClientOptions;

        return KeyVaultBackedCredentialsSource.FromParameterCollectionAsync(
            _inputs,
            _executionInformation,
            _azureUtility,
            _credentialsSourceInputParameterName);
    }

    public void EnsureMsalConfidentialClientIsAuthorized(
        KeyVaultBackedCredentialsSource? credentialsSource = null)
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

        EnsureMsalClientOptionsAvailable();

        EnsureCredentialSourceIsAuthorized(credentialsSource);
    }

    public void EnsureMsalClientOptionsAvailable()
    {
        if (MsalClientOptions is null)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the requested application identity."
                );
        }
    }

    public void EnsureCredentialSourceIsAuthorized(
        KeyVaultBackedCredentialsSource? credentialsSource = null)
    {
        var context = _serviceProvider.Get<IPluginExecutionContext2>();
        if (credentialsSource is null)
        {
            credentialsSource = ClientCredentialsSource;
        }
        else
        {
            credentialsSource.FillMissingPropertiesAsync(_azureUtility)
                .GetAwaiter().GetResult();
        }
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
}
