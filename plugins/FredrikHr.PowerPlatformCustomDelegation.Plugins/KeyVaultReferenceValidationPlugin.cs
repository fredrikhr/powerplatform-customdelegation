using System.ServiceModel;

using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.Resources;

using Microsoft.Xrm.Sdk.Messages;

using FredrikHr.PowerPlatformCustomDelegation.Entities;
using FredrikHr.PowerPlatformSdkExtensions.PluginRuntime;
using FredrikHr.PowerPlatformCustomDelegation.Common;

namespace FredrikHr.PowerPlatformCustomDelegation.Plugins;

public sealed class KeyVaultReferenceValidationPlugin : PluginBase, IPlugin
{
    internal static class InputParameterNames
    {
        internal const string Target = nameof(Target);
    }

    internal static class OutputParameterNames
    {
        internal const string Success = nameof(Success);
        internal const string Result = nameof(Result);
    }

    protected override void ExecuteCore(
        IServiceProvider serviceProvider,
        PluginExecutionInformation info)
    {
        info ??= new(serviceProvider);
        PowerPlatformFicTokenCredential pluginAzureCreds = new(serviceProvider);
        AzureUtility azureUtility = new(pluginAzureCreds);
        var context = serviceProvider.Get<IPluginExecutionContext>();
        ParameterCollection outputs = context.OutputParameters;
        if (!az_keyvaultreference.EntityLogicalName.Equals(context.PrimaryEntityName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid primary entity name. Expected '{az_keyvaultreference.EntityLogicalName}', but '{context.PrimaryEntityName}' was specified."
                );
        }

        az_keyvaultreference targetEntity = context
            .InputParameterOrDefault<az_keyvaultreference?>(InputParameterNames.Target)
            is { az_vaulturi: string, az_name: string, az_vaultobjectidcollectionname: string, az_vaultobjectiduri: string } boundEntity
            ? boundEntity
            : info.SystemDataverseClient.Retrieve(
                az_keyvaultreference.EntityLogicalName,
                context.PrimaryEntityId,
                az_keyvaultreference.ColumnSet
                ).ToEntity<az_keyvaultreference>()
            ;
        if ("Update".Equals(context.MessageName, StringComparison.OrdinalIgnoreCase) &&
            targetEntity.statuscode != az_keyvaultreference_statuscode.New)
        {
            outputs[OutputParameterNames.Result] = "Skipped";
            return;
        }

        Uri targetKeyVaultUri;
        try { targetKeyVaultUri = new(targetEntity.az_vaulturi, UriKind.Absolute); }
        catch (ArgumentException uriArgExcept)
        {
            info.TracingService?.Trace(
                "While retrieving Key Vault URI for record {0}({1}): {2}",
                az_keyvaultreference.EntitySetName,
                targetEntity.Id,
                uriArgExcept.Message
                );
            throw new InvalidPluginExecutionException(
                httpStatus: PluginHttpStatusCode.BadRequest,
                message: $"Invalid value for {az_keyvaultreference.Fields.az_vaulturi} (Value: '{targetEntity.az_vaulturi}'): {uriArgExcept.Message}"
                );
        }

        ResourceIdentifier? keyVaultRootResourceIdentifier =
            azureUtility.GetKeyVaultResourceIdentifier(targetKeyVaultUri)
            .GetAwaiter().GetResult();
        if (keyVaultRootResourceIdentifier is null)
        {
            UpdateRequest targetInactiveRequ = new()
            {
                Target = new az_keyvaultreference()
                {
                    Id = targetEntity.Id,
                    statecode = az_keyvaultreference_statecode.Inactive,
                    statuscode = az_keyvaultreference_statuscode.InvalidKeyVault,
                    az_resourceid = null,
                    az_resourcevalidatedon = null,
                },
            };
            try { info.SystemDataverseClient.Execute(targetInactiveRequ); }
            catch (FaultException<OrganizationServiceFault> targetInactiveExcept)
            {
                info.TracingService?.Trace(
                    "While updating record {0}({1}) to Inactive state: {2}",
                    az_keyvaultreference.EntitySetName,
                    targetEntity.Id,
                    targetInactiveExcept.Message
                    );
            }

            outputs[OutputParameterNames.Success] = false;
            outputs[OutputParameterNames.Result] = "Key Vault not found or inaccessible.";
            return;
        }

        ResourceIdentifier targetArmResourceIdentifier =
            keyVaultRootResourceIdentifier.AppendChildResource(
                targetEntity.az_vaultobjectidcollectionname,
                targetEntity.az_name
                );
        try
        {
            Uri targetKvUri = new(targetEntity.az_vaultobjectiduri, UriKind.Absolute);
            object _ = (targetEntity.az_type ?? az_keyvaultdataobjecttype.Secret) switch
            {
                az_keyvaultdataobjecttype.Certificate or
                az_keyvaultdataobjecttype.CertificatewithX509chain =>
                    KeyVaultPluginUtility.GetKeyVaultCertificateAsync(
                        pluginAzureCreds, new(targetKvUri)
                        ).GetAwaiter().GetResult(),
                az_keyvaultdataobjecttype.Secret or
                _ =>
                    KeyVaultPluginUtility.GetKeyVaultSecretAsync(
                        pluginAzureCreds, new(targetKvUri)
                        ).GetAwaiter().GetResult(),
            };
        }
        catch (Azure.RequestFailedException targetKvResourceExcept)
        {
            info.TracingService?.Trace(
                "While getting Key Vault resource for record {0}({1}); Key Vault Object URI: {2}: {3}",
                az_keyvaultreference.EntitySetName,
                targetEntity.Id,
                targetEntity.az_vaultobjectiduri,
                targetKvResourceExcept.Message
                );
            UpdateRequest targetInactiveRequ = new()
            {
                Target = new az_keyvaultreference()
                {
                    Id = targetEntity.Id,
                    statecode = az_keyvaultreference_statecode.Inactive,
                    statuscode = az_keyvaultreference_statuscode.InvalidReference,
                    az_resourceid = null,
                    az_resourcevalidatedon = null,
                },
            };
            try { info.SystemDataverseClient.Execute(targetInactiveRequ); }
            catch (FaultException<OrganizationServiceFault> targetInactiveExcept)
            {
                info.TracingService?.Trace(
                    "While updating record {0}({1}) to Inactive state: {2}",
                    az_keyvaultreference.EntitySetName,
                    targetEntity.Id,
                    targetInactiveExcept.Message
                    );
            }

            outputs[OutputParameterNames.Success] = false;
            outputs[OutputParameterNames.Result] = targetKvResourceExcept.Message;
            return;
        }

        az_keyvaultreference targetUpdateEntity = new()
        {
            Id = targetEntity.Id,
            az_resourceid = targetArmResourceIdentifier.ToString(),
            az_resourcevalidatedon = DateTime.UtcNow,
            RowVersion = targetEntity.RowVersion,
        };
        if (targetEntity.statecode == az_keyvaultreference_statecode.Active)
            targetUpdateEntity.statuscode = az_keyvaultreference_statuscode.Validated;
        UpdateRequest targetUpdateRequ = new()
        {
            Target = targetUpdateEntity,
            ConcurrencyBehavior = ConcurrencyBehavior.IfRowVersionMatches,
        };
        try { info.SystemDataverseClient.Execute(targetUpdateRequ); }
        catch (FaultException<OrganizationServiceFault> targetUpdateExcept)
        {
            info.TracingService?.Trace(
                "While updating record {0}({1}) with validated ARM Resource ID: {2}",
                az_keyvaultreference.EntitySetName,
                targetEntity.Id,
                targetUpdateExcept.Message
                );
        }

        outputs[OutputParameterNames.Success] = true;
        outputs[OutputParameterNames.Result] = "Successfully validated";
    }
}