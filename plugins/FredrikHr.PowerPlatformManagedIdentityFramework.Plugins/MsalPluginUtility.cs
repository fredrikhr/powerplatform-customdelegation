using Azure.Core;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Identity.Client;
using Microsoft.Xrm.Sdk.Query;

using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

internal sealed class MsalPluginUtility
{
    internal const string FallbackClientId = "00000007-0000-0000-c000-000000000000";
    internal static class InputParameterNames
    {
        internal const string Application = nameof(Application);
        internal const string ClientCredentialsSource = nameof(ClientCredentialsSource);
    }

    private readonly IServiceProvider _serviceProvider;
    private readonly ParameterCollection _inputs;
    private readonly PluginExecutionInformation _executionInformation;
    private readonly TokenCredential _azureCredentials;
    private readonly Lazy<bool> _isApplicationSelfRequest;
    private readonly Lazy<bool> _isPluginIdentityRequest;
    private readonly Lazy<ConfidentialClientApplicationOptions?> _msalClientOptions;

    internal MsalPluginUtility(
        IServiceProvider serviceProvider,
        PluginExecutionInformation executionInformation,
        TokenCredential azureCredentials
        )
    {
        _serviceProvider = serviceProvider;
        var context = serviceProvider.Get<IPluginExecutionContext>();
        _inputs = context.InputParameters;
        _executionInformation = executionInformation;
        _azureCredentials = azureCredentials;

        _isApplicationSelfRequest = new(EvaluateIsApplicationSelfRequest);
        _isPluginIdentityRequest = new(EvaluateIsApplicationPluginIdentityRequest);
        _msalClientOptions = new(ConstructConfidentialClientApplicationOptions);
    }

    internal bool IsApplicationRequestingSelf => _isApplicationSelfRequest.Value;
    internal bool IsRequestedApplicationPluginIdentity => _isPluginIdentityRequest.Value;
    internal ConfidentialClientApplicationOptions? MsalClientOptions => _msalClientOptions.Value;
    internal PluginClientCredentialsSource? ClientCredentialsSource => null;

    internal ConfidentialClientApplicationBuilder CreateMsalClientBuilder()
    {
        var builder = ConfidentialClientApplicationBuilder
            .CreateWithApplicationOptions(MsalClientOptions);

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
                        _azureCredentials
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
                            _azureCredentials,
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

        if (_inputs.TryGetValue(
            InputParameterNames.Application,
            out EntityReference applicationEntityReference))
        {
            return applicationEntityReference.LogicalName switch
            {
                string n when ManagedIdentity.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<ManagedIdentity>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        ManagedIdentity.ColumnSet
                        ) switch
                    {
                        ManagedIdentity mi => ConstructFromManagedIdentity(mi),
                        null => null,
                    },
                string n when SystemUser.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<SystemUser>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        SystemUser.ApplicationUserColumnSet
                        ) switch
                    {
                        SystemUser appUser => ConstructFromSystemUser(appUser),
                        null => null,
                    },
                string n when ApplicationUser.EntityLogicalName.Equals(n, cmp)
                    => GetByEntityReference<ApplicationUser>(
                        _executionInformation.SystemDataverseClient,
                        applicationEntityReference,
                        ApplicationUser.ColumnSet
                        ) switch
                    {
                        ApplicationUser appUser => ConstructFromApplicationUser(appUser),
                        null => null,
                    },
                _ => throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Entity '{SystemUser.EntityLogicalName}' specified for {InputParameterNames.Application}, but only the following entities are allowed: {ManagedIdentity.EntityLogicalName}, {SystemUser.EntityLogicalName}, {ApplicationUser.EntityLogicalName}"
                    ),
            };

            static T? GetByEntityReference<T>(
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

        return _executionInformation.ApplicationSystemUser is SystemUser user
            ? ConstructFromSystemUser(user)
            : null
            ;

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
                ClientName = managedIdentity.Name ?? managedIdentity.LogicalName,
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
}
