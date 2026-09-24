using Azure.ResourceManager;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

internal sealed class AzurePluginUtility(IServiceProvider serviceProvider)
{
    internal ArmClient ArmClient => field ??= new(PluginAzureTokenCredential);

    internal PowerPlatformFicTokenCredential PluginAzureTokenCredential =>
        field ??= new(serviceProvider);
}
