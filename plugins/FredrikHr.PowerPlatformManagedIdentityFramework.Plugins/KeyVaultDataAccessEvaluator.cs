using System.Text.RegularExpressions;

using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using Azure.ResourceManager.Resources;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins;

internal sealed class KeyVaultDataAccessEvaluator(
    ArmClient armClient,
    ResourceIdentifier keyVaultObjectResourceIdentifier,
    Guid entraIdPrincipalObjectId)
{
    public ArmClient ArmClient { get; } = armClient;
    public ResourceIdentifier KeyVaultObjectResourceIdentifier { get; } =
        keyVaultObjectResourceIdentifier;
    public Guid EntraIdPrincipalObjectId { get; } = entraIdPrincipalObjectId;
    public GenericResource KeyVaultGenericResource { get; } =
        armClient.GetGenericResource(keyVaultObjectResourceIdentifier);

    private List<ResourceIdentifier> RolesDenyGetSecretValue { get; } = [];
    private List<ResourceIdentifier> RolesDenyReadCertificate { get; } = [];
    private List<ResourceIdentifier> RolesDenySignWithKey { get; } = [];
    private List<ResourceIdentifier> RolesAllowGetSecretValue { get; } = [];
    private List<ResourceIdentifier> RolesAllowReadCertificate { get; } = [];
    private List<ResourceIdentifier> RolesAllowSignWithKey { get; } = [];

    public async Task<KeyVaultDataAccessPermisions> EvaluateAccessAsync()
    {
        AuthorizationRoleDefinitionCollection roleDefinitions =
            KeyVaultGenericResource.GetAuthorizationRoleDefinitions();
        await EvaluateRoleDefinitionsAsync(roleDefinitions)
            .ConfigureAwait(continueOnCapturedContext: false);
        return await EvaluateAccessPermissionsAsync()
            .ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task EvaluateRoleDefinitionsAsync(
        AuthorizationRoleDefinitionCollection roleDefinitions)
    {
        AsyncPageable<AuthorizationRoleDefinitionResource> builtInRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'BuiltInRole'");
        await EvaluateRoleDefinitionsAsync(builtInRoleDefinitions)
            .ConfigureAwait(continueOnCapturedContext: false);
        AsyncPageable<AuthorizationRoleDefinitionResource> customRoleDefinitions =
            roleDefinitions.GetAllAsync(filter: "type eq 'CustomRole'");
        await EvaluateRoleDefinitionsAsync(customRoleDefinitions)
            .ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task EvaluateRoleDefinitionsAsync(
        AsyncPageable<AuthorizationRoleDefinitionResource> roleDefinitions)
    {
        await foreach (AuthorizationRoleDefinitionResource roleDefinition in
            roleDefinitions.ConfigureAwait(continueOnCapturedContext: false))
        {
            EvaluateRoleDefinition(roleDefinition);
        }
    }

    private static readonly Regex DataActionWildcardRegex =
        new("(?<=^|\\/)\\*(?=$|\\/)");

    private const string GetSecretAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action";
    private const string ReadCertificateAction = "Microsoft.KeyVault/vaults/certificates/read";
    private const string SignWithKeyAction = "Microsoft.KeyVault/vaults/keys/sign/action";

    private void EvaluateRoleDefinition(
        AuthorizationRoleDefinitionResource roleDefinition)
    {
        bool anyDenied = false;
        foreach (RoleDefinitionPermission rolePermission in roleDefinition.Data.Permissions)
        {
            foreach (string deniedDataAction in rolePermission.NotDataActions)
            {
                if (IsDataActionMatch(deniedDataAction, GetSecretAction))
                {
                    anyDenied = true;
                    RolesDenyGetSecretValue.Add(roleDefinition.Id);
                }
                if (IsDataActionMatch(deniedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    RolesDenyReadCertificate.Add(roleDefinition.Id);
                }
                if (IsDataActionMatch(deniedDataAction, SignWithKeyAction))
                {
                    anyDenied = true;
                    RolesDenySignWithKey.Add(roleDefinition.Id);
                }
            }
            if (anyDenied) continue;
            foreach (string allowedDataAction in rolePermission.DataActions)
            {
                if (IsDataActionMatch(allowedDataAction, GetSecretAction))
                {
                    anyDenied = true;
                    RolesAllowGetSecretValue.Add(roleDefinition.Id);
                }
                if (IsDataActionMatch(allowedDataAction, ReadCertificateAction))
                {
                    anyDenied = true;
                    RolesAllowReadCertificate.Add(roleDefinition.Id);
                }
                if (IsDataActionMatch(allowedDataAction, SignWithKeyAction))
                {
                    anyDenied = true;
                    RolesAllowSignWithKey.Add(roleDefinition.Id);
                }
            }
        }
    }

    private static bool IsDataActionMatch(string dataActionTemplate, string dataAction)
    {
        if (!DataActionWildcardRegex.IsMatch(dataActionTemplate))
        {
            return dataActionTemplate.Equals(dataAction, StringComparison.OrdinalIgnoreCase);
        }

        string[] dataActionPartials = DataActionWildcardRegex.Split(dataActionTemplate);
        string dataActionRegexPattern = $"^{string.Join("[^\\/].*", dataActionPartials.Select(Regex.Escape))}$";
        return Regex.IsMatch(dataAction, dataActionRegexPattern);
    }

    private async Task<KeyVaultDataAccessPermisions> EvaluateAccessPermissionsAsync()
    {
        KeyVaultDataAccessPermisions possiblePermissions =
            KeyVaultDataAccessPermisions.GetSecret |
            KeyVaultDataAccessPermisions.ReadCertificateProperties |
            KeyVaultDataAccessPermisions.SignWithKey;
        KeyVaultDataAccessPermisions effectivePermissions =
            KeyVaultDataAccessPermisions.None;

        string assignmentFilter = $"atScope() and assignedTo('{EntraIdPrincipalObjectId}')";
        static bool IsGetSecretDataActionMatch(string dataActionTemplate) =>
                IsDataActionMatch(dataActionTemplate, GetSecretAction);
        static bool IsReadCertificateDataActionMatch(string dataActionTemplate) =>
            IsDataActionMatch(dataActionTemplate, ReadCertificateAction);
        static bool IsSignWithKeyDataActionMatch(string dataActionTemplate) =>
            IsDataActionMatch(dataActionTemplate, SignWithKeyAction);

        await foreach (DenyAssignmentResource denyAssignment in
            KeyVaultGenericResource.GetDenyAssignments().GetAllAsync(assignmentFilter)
            .ConfigureAwait(continueOnCapturedContext: false))
        {
            foreach (DenyAssignmentPermission denyPermission in denyAssignment.Data.Permissions)
            {
                if (denyPermission.DataActions.Any(IsGetSecretDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsGetSecretDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.GetSecret;
                }

                if (denyPermission.DataActions.Any(IsReadCertificateDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsReadCertificateDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.ReadCertificateProperties;
                }

                if (denyPermission.DataActions.Any(IsSignWithKeyDataActionMatch) &&
                    !denyPermission.NotDataActions.Any(IsSignWithKeyDataActionMatch))
                {
                    possiblePermissions &= ~KeyVaultDataAccessPermisions.SignWithKey;
                }
            }
        }

        List<RoleAssignmentResource> roleAssignments = [];
        await foreach (RoleAssignmentResource roleAssignment in
            KeyVaultGenericResource.GetRoleAssignments().GetAllAsync(assignmentFilter)
            .ConfigureAwait(continueOnCapturedContext: false))
        {
            roleAssignments.Add(roleAssignment);
        }

        foreach (RoleAssignmentResource roleAssignment in roleAssignments)
        {
            if (RolesDenyGetSecretValue.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                possiblePermissions &= ~KeyVaultDataAccessPermisions.GetSecret;
            }
            if (RolesDenyReadCertificate.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                possiblePermissions &= ~KeyVaultDataAccessPermisions.ReadCertificateProperties;
            }
            if (RolesDenySignWithKey.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                possiblePermissions &= ~KeyVaultDataAccessPermisions.SignWithKey;
            }
        }
        foreach (RoleAssignmentResource roleAssignment in roleAssignments)
        {
            if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.GetSecret) &&
                RolesAllowGetSecretValue.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                effectivePermissions |= KeyVaultDataAccessPermisions.GetSecret;
            }
            if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.ReadCertificateProperties) &&
                RolesAllowReadCertificate.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                effectivePermissions |= KeyVaultDataAccessPermisions.ReadCertificateProperties;
            }
            if (possiblePermissions.HasFlag(KeyVaultDataAccessPermisions.SignWithKey) &&
                RolesAllowSignWithKey.Contains(roleAssignment.Data.RoleDefinitionId))
            {
                effectivePermissions |= KeyVaultDataAccessPermisions.SignWithKey;
            }
        }

        return effectivePermissions;
    }
}