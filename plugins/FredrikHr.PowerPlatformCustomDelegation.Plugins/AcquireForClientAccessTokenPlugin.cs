using Microsoft.Identity.Client;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

using Azure.Core;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime.Entities;
using FredrikHr.PowerPlatformCustomDelegation.Common;

namespace FredrikHr.PowerPlatformCustomDelegation.Plugins;

public sealed class AcquireForClientAccessTokenPlugin()
    : AcquireAccessTokenPlugin(), IPlugin
{
    internal static class InputParameterNames
    {
        internal const string Resource = nameof(Resource);
    }

    protected override string AcquireAccessTokenCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info)
    {
        _ = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        info ??= new(serviceProvider);
        AzureUtility azureUtility = new(new PowerPlatformFicTokenCredential(serviceProvider));
        MsalPluginUtility msalUtility = new(serviceProvider, info);
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        ParameterCollection inputs = context.InputParameters;

        _ = inputs.TryGetValue(
            InputParameterNames.Resource,
            out string? resource
            );
        if (string.IsNullOrEmpty(resource))
        {
            resource = info.ApplicationSystemUser?.ApplicationId?.ToString();
            if (string.IsNullOrEmpty(resource))
            {
                throw new InvalidPluginExecutionException(
                    httpStatus: PluginHttpStatusCode.BadRequest,
                    message: $"Missing input parameter '{InputParameterNames.Resource}'."
                    );
            }
        }
        string[] scopes = [$"{resource}/.default"];

        if (!msalUtility.IsApplicationRequestingSelf &&
            !info.UserHasImpersonationPrivilege)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"User (Entra ID Object ID: {context.UserAzureActiveDirectoryObjectId}, Dataverse System User ID: {context.UserId}) does not have required privilege '{PluginExecutionInformation.PrivilegeNameImpersonation}'."
                );
        }

        if (msalUtility.IsRequestedApplicationPluginIdentity)
        {
            var pluginFicProvider = serviceProvider
                .Get<IManagedIdentityService>();
            return pluginFicProvider.AcquireToken(scopes);
        }

        if (msalUtility.MsalClientOptions is null)
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the application for which an access token should be acquired."
                );
        }

        msalUtility.FillMissingCredentialSourcePropertiesAsync()
            .GetAwaiter().GetResult();
        if (msalUtility.ClientCredentialsSource is not { KeyVaultObjectResourceIdentifier: ResourceIdentifier kvObjArmId })
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Missing required input parameters specifying the credential source from Key Vault to authenticate the requested application identity."
                );
        }

        KeyVaultDataAccessEvaluator kvAccessEval = new(
            azureUtility.ArmClient,
            kvObjArmId,
            context.UserAzureActiveDirectoryObjectId
            );
        KeyVaultDataAccessPermisions kvAccessPerms = kvAccessEval
            .EvaluateAccessAsync()
            .GetAwaiter().GetResult();
        switch (msalUtility.ClientCredentialsSource.KeyVaultObjectType)
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

        IConfidentialClientApplication msalClient = msalUtility
            .CreateMsalClientBuilder()
            .Build();
        AcquireTokenForClientParameterBuilder msalAcquire =
            msalClient.AcquireTokenForClient(scopes);
        AuthenticationResult msalAuthResult = msalAcquire.ExecuteAsync()
            .GetAwaiter().GetResult();
        return msalAuthResult.AccessToken;
    }
}
