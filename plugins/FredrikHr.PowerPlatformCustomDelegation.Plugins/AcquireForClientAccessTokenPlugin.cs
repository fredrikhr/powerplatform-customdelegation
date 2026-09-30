using Microsoft.Identity.Client;

using FredrikHr.PowerPlatformCustomDelegation.Common;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

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
        MsalPluginUtility msalUtility = new(serviceProvider, info, azureUtility);
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

        msalUtility.EnsureMsalConfidentialClientIsAuthorized();

        if (msalUtility.IsRequestedApplicationPluginIdentity)
        {
            var pluginFicProvider = serviceProvider
                .Get<IManagedIdentityService>();
            return pluginFicProvider.AcquireToken(scopes);
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
