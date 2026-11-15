using Microsoft.Xrm.Sdk.Query;

namespace FredrikHr.PowerPlatformCustomDelegation.Entities;

partial class msal_confidentialclientconfiguration
{
    public static ColumnSet ColumnSet { get; } = new(
        Fields.msal_clientcredentialsid,
        Fields.msal_clientinfoid,
        Fields.msal_clientcredentialsid,
        Fields.statecode,
        Fields.statuscode,
        Fields.VersionNumber
        );
}