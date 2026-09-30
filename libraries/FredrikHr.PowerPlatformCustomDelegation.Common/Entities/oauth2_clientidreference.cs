using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformCustomDelegation.Entities;

partial class oauth2_clientidreference
{
    public static ColumnSet ColumnSet { get; } = new(
        Fields.oauth2_clientidreferenceId,
        Fields.oauth2_displayname,
        Fields.oauth2_clientid,
        Fields.oidc_authorityurl,
        Fields.msal_instancediscoveryjson,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber
        );
}