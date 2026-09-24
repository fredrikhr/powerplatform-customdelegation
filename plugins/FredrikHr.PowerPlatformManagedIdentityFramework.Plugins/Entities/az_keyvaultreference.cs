using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformManagedIdentityFramework.Plugins.Entities;

partial class az_keyvaultreference
{
    public static ColumnSet ColumnSet { get; } = new(
        Fields.az_keyvaultreferenceId,
        Fields.az_displayname,
        Fields.az_vaulturi,
        Fields.az_type,
        Fields.az_name,
        Fields.az_version,
        Fields.az_vaultobjectiduri,
        Fields.az_vaultobjectidcollectionname,
        Fields.az_resourceid,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber
    );
}