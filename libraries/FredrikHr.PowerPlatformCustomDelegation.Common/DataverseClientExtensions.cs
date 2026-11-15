using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformCustomDelegation.Common;

internal static class DataverseClientExtensions
{
    private static readonly ColumnSet AllColumnsColumnSet = new(allColumns: true);

    extension(IOrganizationService dataverseClient)
    {
        internal T? GetByEntityReference<T>(
            EntityReference entityReference,
            ColumnSet? columnSet = null)
            where T : Entity
        {
            columnSet ??= AllColumnsColumnSet;
            return dataverseClient.Retrieve(entityReference.LogicalName, entityReference.Id, columnSet) switch
            {
                T t => t,
                Entity e => e.ToEntity<T>(),
                _ => null,
            };
        }
    }
}