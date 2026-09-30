using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformCustomDelegation.Entities;

partial class entra_serviceprincipalreference
{
    public static ColumnSet ColumnSet { get; } = new(
        Fields.entra_serviceprincipalreferenceId,
        Fields.entra_displayname,
        Fields.entra_clientid,
        Fields.entra_instance,
        Fields.entra_tenant,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber
        );
}