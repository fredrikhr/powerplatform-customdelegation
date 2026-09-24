using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Common;

public abstract class AcquireAccessTokenPlugin() : PluginBase()
{
    internal static class OutputParameterNames
    {
        internal const string AccessToken = nameof(AccessToken);
        internal const string TokenInformation = nameof(TokenInformation);
    }

    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        var context = serviceProvider.Get<IPluginExecutionContext2>();
        ParameterCollection outputs = context.OutputParameters;

        string accessToken = AcquireAccessToken(serviceProvider, info);
        Entity? jwtEntity = JwtUtility.GetJwtEntity(accessToken);

        outputs[OutputParameterNames.AccessToken] = accessToken;
        outputs[OutputParameterNames.TokenInformation] = jwtEntity;
    }

    protected virtual string AcquireAccessToken(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        )
    {
        return AcquireAccessTokenCore(serviceProvider, info);
    }

    protected abstract string AcquireAccessTokenCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info
        );
}