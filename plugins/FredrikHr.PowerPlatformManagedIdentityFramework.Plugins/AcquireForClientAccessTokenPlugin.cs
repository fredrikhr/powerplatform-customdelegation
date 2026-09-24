using Microsoft.Identity.Client;

using FredrikHr.PowerPlatformManagedIdentityFramework.Common;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

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
        AzurePluginUtility azureUtility = new(serviceProvider);
        MsalPluginUtility msalUtility = new(serviceProvider, info, azureUtility.PluginAzureTokenCredential);
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
